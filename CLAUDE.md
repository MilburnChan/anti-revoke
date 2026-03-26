# Project Contract: antirevoke

## Build

```bash
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
```

## Inject & Test

```bash
# 注入 WeChat（需要先关闭 WeChat）
DYLD_INSERT_LIBRARIES=$(pwd)/antirevoke.dylib /Applications/WeChat.app/Contents/MacOS/WeChat

# 查看实时日志
tail -f /tmp/antirevoke_*.log
```

## Architecture

- 目标：build 36603（WeChat macOS）
- 策略：hook `isRevokeMessage` via guard variable → 强制返回 FALSE
- 备用：在 constructor 运行前，通过 `0x4294e2c` 处二进制 patch 提供兜底
- guard 变量地址：`0x8f8b2a8`（ASLR slide 运行时计算）

## Key Addresses (build 36603)

| Symbol | VA |
|--------|----|
| `IS_REVOKE_MSG_GUARD_VA` | `0x8f8b2a8` |
| binary patch | `0x4294e2c` |

## NEVER

- 修改 `IS_REVOKE_MSG_GUARD_VA` 或 patch offset 时不先验证 build 号。
- 在不确认 WeChat 版本的前提下执行注入。

## Verification

1. Build 无 warning：`clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c`
2. 启动后日志出现 `[antirevoke] guard set` 表示 hook 生效
3. 发送消息后对方撤回，消息应仍然可见
