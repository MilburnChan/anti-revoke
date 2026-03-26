/**
 * antirevoke.dylib — WeChat Anti-Revoke Hook for macOS (build 36603)
 *
 * Strategy:
 *   Layer 1 — binary patch at 0x4294e2c (fallback, pre-constructor)
 *   Layer 2 — guard variable hook: isRevokeMessage always returns FALSE
 *   Layer 3 — in-window revoke indicator via NSWindow subtitle
 *              (no class enumeration; no external notifications)
 *
 * Build:
 *   clang -dynamiclib -arch arm64 -framework Foundation -lobjc \
 *         -o antirevoke.dylib antirevoke.c
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdlib.h>
#include <pthread.h>
#include <mach-o/dyld.h>
#include <unistd.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <dispatch/dispatch.h>

/* ------------------------------------------------------------------ */
/* Addresses — build 36603                                             */
/* ------------------------------------------------------------------ */
#define IS_REVOKE_MSG_GUARD_VA  0x8f8b2a8
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

/* Extract text content of an XML tag into buf (null-terminated) */
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
/* Revoked ID set — persistent across WeChat restarts                  */
/* ------------------------------------------------------------------ */
#define MAX_REVOKED 8192
#define REVOKE_PERSIST "/tmp/antirevoke_revoked.txt"

static uint64_t        g_revoked[MAX_REVOKED];
static int             g_nrevoked = 0;
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

static void revoked_load(void) {
    FILE *f = fopen(REVOKE_PERSIST, "r");
    if (!f) return;
    char line[32];
    while (fgets(line, sizeof(line), f) && g_nrevoked < MAX_REVOKED) {
        uint64_t id = strtoull(line, NULL, 10);
        if (id) g_revoked[g_nrevoked++] = id;
    }
    fclose(f);
    logmsg("[revoked] loaded %d ids from disk\n", g_nrevoked);
}

static void revoked_add(uint64_t id) {
    if (!id) return;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < g_nrevoked; i++)
        if (g_revoked[i] == id) { pthread_mutex_unlock(&g_lock); return; }
    if (g_nrevoked < MAX_REVOKED) g_revoked[g_nrevoked++] = id;
    pthread_mutex_unlock(&g_lock);
    FILE *f = fopen(REVOKE_PERSIST, "a");
    if (f) { fprintf(f, "%llu\n", (unsigned long long)id); fclose(f); }
}

/* ------------------------------------------------------------------ */
/* In-window revoke indicator — injects NSTextField into contentView   */
/* NSRect on ARM64: 4 doubles = HFA, returned/passed in v0-v3.        */
/* ------------------------------------------------------------------ */
typedef struct { double x, y, width, height; } MyRect;

static void show_revoke_indicator(void *ctx) {
    char *info = (char *)ctx;
    if (!info) return;

    id app = ((id(*)(Class,SEL))objc_msgSend)(
        objc_getClass("NSApplication"), sel_registerName("sharedApplication"));
    if (!app) { free(info); return; }
    id win = ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("keyWindow"));
    if (!win) { free(info); return; }

    logmsg("[indicator] window class: %s\n", class_getName(object_getClass(win)));

    id cv = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("contentView"));
    if (!cv) { free(info); return; }

    /* Get contentView bounds (HFA: returned in v0-v3 on ARM64) */
    MyRect bounds = ((MyRect(*)(id,SEL))objc_msgSend)(cv, sel_registerName("bounds"));
    logmsg("[indicator] bounds: %.0f x %.0f\n", bounds.width, bounds.height);

    /* Create label at bottom of contentView, full width, 28px tall */
    MyRect frame = {0.0, 0.0, bounds.width > 0 ? bounds.width : 400.0, 28.0};

    id label = ((id(*)(id,SEL))objc_msgSend)(
        (id)objc_getClass("NSTextField"), sel_registerName("alloc"));
    label = ((id(*)(id,SEL,MyRect))objc_msgSend)(
        label, sel_registerName("initWithFrame:"), frame);
    if (!label) { free(info); return; }

    /* Configure: non-editable, no border, draws background */
    ((void(*)(id,SEL,int))objc_msgSend)(label, sel_registerName("setEditable:"),        0);
    ((void(*)(id,SEL,int))objc_msgSend)(label, sel_registerName("setBezeled:"),         0);
    ((void(*)(id,SEL,int))objc_msgSend)(label, sel_registerName("setDrawsBackground:"), 1);
    ((void(*)(id,SEL,int))objc_msgSend)(label, sel_registerName("setAlignment:"),       2); /* center */

    id yellow = ((id(*)(Class,SEL))objc_msgSend)(
        objc_getClass("NSColor"), sel_registerName("yellowColor"));
    if (yellow)
        ((void(*)(id,SEL,id))objc_msgSend)(label, sel_registerName("setBackgroundColor:"), yellow);
    id black = ((id(*)(Class,SEL))objc_msgSend)(
        objc_getClass("NSColor"), sel_registerName("blackColor"));
    if (black)
        ((void(*)(id,SEL,id))objc_msgSend)(label, sel_registerName("setTextColor:"), black);

    id nsstr = ((id(*)(Class,SEL,const char*))objc_msgSend)(
        objc_getClass("NSString"), sel_registerName("stringWithUTF8String:"), info);
    ((void(*)(id,SEL,id))objc_msgSend)(label, sel_registerName("setStringValue:"), nsstr);

    /* Add above all existing subviews (NSWindowAbove = 1) */
    ((void(*)(id,SEL,id,int,id))objc_msgSend)(
        cv, sel_registerName("addSubview:positioned:relativeTo:"),
        label, 1, (id)0);

    logmsg("[indicator] label added\n");

    /* Remove after 8 seconds */
    id retained = ((id(*)(id,SEL))objc_msgSend)(label, sel_registerName("retain"));
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, 8 * NSEC_PER_SEC),
        dispatch_get_main_queue(),
        ^{
            ((void(*)(id,SEL))objc_msgSend)(retained, sel_registerName("removeFromSuperview"));
            ((void(*)(id,SEL))objc_msgSend)(retained, sel_registerName("release"));
        }
    );

    free(info);
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

    if (newmsgid) revoked_add(newmsgid);
    if (msgid)    revoked_add(msgid);

    /* Build subtitle string and dispatch to main thread */
    char *info = malloc(256);
    if (info) {
        snprintf(info, 256, "𝟚𝕏𝟚𝕃 𝚌𝚊𝚕𝚕𝚒𝚗𝚐 𝙲𝚀");
        dispatch_async_f(dispatch_get_main_queue(), info,
                         (dispatch_function_t)show_revoke_indicator);
    }

    return 0;  /* FALSE: block revoke, original message preserved */
}

/* ------------------------------------------------------------------ */
/* Constructor                                                         */
/* ------------------------------------------------------------------ */
__attribute__((constructor))
static void antirevoke_init(void) {
    logmsg("[init] antirevoke loaded, pid=%d\n", getpid());

    revoked_load();

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
    logmsg("[init] isRevokeMessage guard set\n");

    logmsg("[init] setup complete\n");
}
