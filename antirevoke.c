/**
 * antirevoke.dylib — WeChat Anti-Revoke Hook for macOS (build 36603)
 *
 * Strategy (stable):
 *   Hook isRevokeMessage via guard variable → return FALSE
 *   This prevents the revoke action from being created, so the original
 *   message is never hidden. The binary patch at 0x4294e2c serves as
 *   fallback when the guard has not been set yet (before constructor runs).
 *
 * Result: original message preserved, no revoke notification shown.
 *
 * Build: clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <mach-o/dyld.h>
#include <unistd.h>

/* --- Addresses for build 36603 --- */
#define IS_REVOKE_MSG_GUARD_VA  0x8f8b2a8
#define MSG_TYPE_OFFSET         0x0c
#define TYPE_REVOKE             10002

/* --- Debug log --- */
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

static uintptr_t wechat_base = 0;

/* --- isRevokeMessage hook --- */
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

    logmsg("[revoke] type 10002 → returning FALSE (block revoke)\n");
    return 0;  /* FALSE: block revoke action, original message preserved */
}

/* --- Constructor --- */
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

    /* Hook isRevokeMessage via guard variable → always return FALSE */
    void **guard = (void **)(wechat_base + IS_REVOKE_MSG_GUARD_VA);
    *guard = (void *)hook_isRevokeMessage;
    logmsg("[init] isRevokeMessage guard set → return FALSE\n");

    logmsg("[init] setup complete\n");
}
