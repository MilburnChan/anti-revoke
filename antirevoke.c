/**
 * antirevoke.dylib — WeChat anti-revoke hook for macOS.
 *
 * Strategy:
 *   Layer 1 — binary patch: isRevokeMessage() returns FALSE before constructor
 *   Layer 2 — guard variable hook: isRevokeMessage() keeps returning FALSE
 *
 * Build:
 *   clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
 *
 * patch_wechat.py resolves IS_REVOKE_MSG_GUARD_VA from the installed
 * wechat.dylib and passes it in via -D at build time.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <mach/mach_time.h>

/* ------------------------------------------------------------------ */
/* Addresses                                                            */
/* ------------------------------------------------------------------ */
#ifndef IS_REVOKE_MSG_GUARD_VA
#define IS_REVOKE_MSG_GUARD_VA  0x8f8b2a8
#endif
#define MSG_TYPE_OFFSET         0x0c
#define MSG_SENDER_OFFSET       0x18   /* SSO string: sender wxid      */
#define MSG_XML_OFFSET          0x138  /* SSO string: revoke XML       */
#define TYPE_REVOKE             10002

/* ------------------------------------------------------------------ */
/* Debug log                                                           */
/* ------------------------------------------------------------------ */
static FILE *logfp = NULL;
static void logmsg(const char *fmt, ...) {
    if (!logfp) {
        char path[256];
        snprintf(path, sizeof(path), "/tmp/antirevoke_%d.log", getpid());
        logfp = fopen(path, "a");
        if (!logfp) return;
    }
    va_list ap;
    va_start(ap, fmt);
    vfprintf(logfp, fmt, ap);
    va_end(ap);
    fflush(logfp);
}

/* ------------------------------------------------------------------ */
/* SSO string helper (libc++ ARM64)                                    */
/* ------------------------------------------------------------------ */
static const char *sso_data(const void *s) {
    const uint8_t *b = (const uint8_t *)s;
    return (b[23] & 0x80) ? *(const char **)b : (const char *)b;
}

/* ------------------------------------------------------------------ */
/* XML field extraction                                                */
/* ------------------------------------------------------------------ */
static uint64_t xml_u64(const char *xml, const char *tag) {
    if (!xml || !*xml) return 0;
    char open[64];
    snprintf(open, sizeof(open), "<%s>", tag);
    const char *p = strstr(xml, open);
    if (!p) return 0;
    return strtoull(p + strlen(open), NULL, 10);
}

static void xml_str(const char *xml, const char *tag, char *buf, size_t bufsz) {
    buf[0] = '\0';
    char open[64], close[64];
    snprintf(open,  sizeof(open),  "<%s>",  tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    const char *p = strstr(xml, open);
    if (!p) return;
    p += strlen(open);
    const char *e = strstr(p, close);
    if (!e) return;
    size_t len = (size_t)(e - p);
    if (len >= bufsz) len = bufsz - 1;
    memcpy(buf, p, len);
    buf[len] = '\0';
}

/* ------------------------------------------------------------------ */
/* isRevokeMessage hook                                                */
/* ------------------------------------------------------------------ */
static uintptr_t wechat_base = 0;

int hook_isRevokeMessage_impl(void *msg, void *lr);

__attribute__((naked))
void hook_isRevokeMessage(void) {
    __asm__ volatile(
        "stp x29, x30, [sp, #-16]!\n"
        "mov x29, sp\n"
        "mov x1, x30\n"
        "bl _hook_isRevokeMessage_impl\n"
        "ldp x29, x30, [sp], #16\n"
        "ret\n"
    );
}

int hook_isRevokeMessage_impl(void *msg, void *lr) {
    int32_t type = *(int32_t *)((char *)msg + MSG_TYPE_OFFSET);
    if (type != TYPE_REVOKE) return 0;

    /* Parse sender */
    const char *sender = sso_data((char *)msg + MSG_SENDER_OFFSET);

    /* Parse revoke XML */
    const char *xml = sso_data((char *)msg + MSG_XML_OFFSET);
    uint64_t newmsgid = xml_u64(xml, "newmsgid");
    uint64_t msgid    = xml_u64(xml, "msgid");
    char replacemsg[128] = "";
    if (xml && *xml) xml_str(xml, "replacemsg", replacemsg, sizeof(replacemsg));

    logmsg("[revoke] sender=%s msgid=%llu newmsgid=%llu replace=%s\n",
           sender ? sender : "?",
           (unsigned long long)msgid,
           (unsigned long long)newmsgid,
           replacemsg);

    int is_self_text = (replacemsg[0] != '\0' &&
                        strstr(replacemsg, "\xe4\xbd\xa0\xe6\x92\xa4\xe5\x9b\x9e") != NULL);
    int is_malformed = (!sender || !*sender) && msgid == 0 && newmsgid == 0;

    /* macOS-initiated self-revoke produces a malformed companion packet;
       phone-initiated self-revoke does not.  Use a time window to pair them. */
    static uint64_t g_malformed_ts = 0;
    static uint64_t g_self_ts = 0;

    uint64_t now = mach_absolute_time();
    const uint64_t WINDOW = 24000000ULL * 2;

    if (is_malformed) {
        g_malformed_ts = now;
        logmsg("[revoke] malformed packet → passthrough\n");
        return 1;
    }

    if (is_self_text) {
        g_self_ts = now;
        int from_macos = (g_malformed_ts && (now - g_malformed_ts) < WINDOW);
        logmsg("[revoke] self-revoke, from_macos=%d\n", from_macos);
        if (from_macos) {
            return 1;  /* macOS-initiated: passthrough to avoid crash */
        }
        /* Phone-initiated self-revoke: fall through to block */
    }

    /* ---- Others' revoke (or phone self-revoke): BLOCK ---- */
    return 0;  /* FALSE: block revoke, original message preserved */
}

/* ------------------------------------------------------------------ */
/* Constructor                                                         */
/* ------------------------------------------------------------------ */
__attribute__((constructor))
static void antirevoke_init(void) {
    logmsg("[init] antirevoke loaded, pid=%d\n", getpid());

    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "wechat.dylib")) {
            wechat_base = (uintptr_t)_dyld_get_image_vmaddr_slide(i);
            logmsg("[init] wechat.dylib slide=0x%lx\n", (unsigned long)wechat_base);
            break;
        }
    }
    if (!wechat_base) {
        logmsg("[init] ERROR: wechat.dylib not found\n");
        return;
    }

    /* Layer 2: hook isRevokeMessage via guard variable */
    void **guard = (void **)(wechat_base + IS_REVOKE_MSG_GUARD_VA);
    *guard = (void *)hook_isRevokeMessage;
    logmsg("[init] isRevokeMessage guard set @ 0x%lx\n",
           (unsigned long)IS_REVOKE_MSG_GUARD_VA);

    logmsg("[init] setup complete\n");
}
