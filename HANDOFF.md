# Handoff: antirevoke (build 36603)

## 当前状态

| 功能 | 状态 |
|------|------|
| 防撤回（原消息保留） | ✅ 稳定 |
| 保留"xxx撤回了一条消息"通知 | ❌ 未解决 |

## 关键地址（build 36603）

| 用途 | VA | Guard VA |
|------|----|----------|
| isRevokeMessage | `0x4294e1c` | `0x8f8b2a8` ← 当前 hook 目标 |
| binary patch fallback | `0x4294e2c` | — |
| 通知插入 BL[22] | `0x3f41700` | `0x8f5fd40` |
| WCDB写 BL[11] | `0x5f3f040` | `0x86f0860` ← 疑似删除原消息 |
| WCDB写 BL[13] | `0x5f3f160` | `0x8aea220` ← 疑似删除原消息 |
| WCDB写 BL[15] | `0x5f3ef98` | `0x8aea130` ← 疑似删除原消息 |
| WCDB写 BL[17] | `0x5f3f040` | — ← 疑似写通知记录 |

VA → 文件偏移：`file_offset = 0x97C8000 + VA`（arm64 slice 基址）

## 两层防御（已上线）

1. **Binary patch**（fallback）：patch `0x4294e2c`，`mov w0,#0; ret`
2. **Guard hook**（主路径）：运行时写 `0x8f8b2a8` → `hook_isRevokeMessage`

## 待解决：通知保留问题

**核心矛盾**：删除原消息和写通知都调用同一 WCDB 模板函数（`0x5f3f040` 等），guard variable hook 无法区分两次调用。

**已排除方案**：
- BL[5] `0x40fb210`（guard `0x8f72b78`）→ 非删除点
- BL[16] `0x40feaa4`（guard `0x8f72c60`）→ 非删除点，但返回0时消息删除+通知保留（有进展）

**下一步（优先级排序）**：
1. 反汇编 `0x5f3f040`/`0x5f3f160`/`0x5f3ef98`，分析调用参数区别（删除 vs 写通知）
2. 测试 BL[7] `0x40c6e24`（guard `0x8f705a8`），调用2次，可能是决策点
3. 参考 Path B 框架（见 readme.md）逐个测试候选 guard

## 关键约束

- WCDB 用 SQLCipher 加密，无法直接读写 DB
- sqlite3 静态编译入 wechat.dylib，符号全 strip，无法 hook
- 消息在 isRevokeMessage 被调用前已持久化到 DB
- UI 从 DB 读取 → 内存修改无效

## 快速开始

```bash
# 编译
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c

# 安装（需 sudo，自动重签名）
sudo python3 patch_wechat.py --backup

# 注入测试（不修改文件）
DYLD_INSERT_LIBRARIES=$(pwd)/antirevoke.dylib /Applications/WeChat.app/Contents/MacOS/WeChat

# 日志
tail -f /tmp/antirevoke_*.log
```
