# Project Contract: antirevoke

## Build

```bash
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
```

说明：正常安装应通过 `patch_wechat.py` 触发编译，因为它会把自动解析出的 `IS_REVOKE_MSG_GUARD_VA` 通过 `-D` 注入。

## Inject & Test

```bash
# 注入 WeChat（需要先关闭 WeChat）
DYLD_INSERT_LIBRARIES=$(pwd)/antirevoke.dylib /Applications/WeChat.app/Contents/MacOS/WeChat

# 查看实时日志
tail -f /tmp/antirevoke_*.log
```

## Architecture

- 目标：WeChat macOS 4.1.8（Apple Silicon）
- 策略：hook `isRevokeMessage` via guard variable → 强制返回 FALSE
- 备用：在 constructor 运行前，通过 `isRevokeMessage` 起始处二进制 patch 提供兜底
- patch site / guard 地址：由 `patch_wechat.py` 从当前 `wechat.dylib` 自动解析

## Key Addresses

- 运行时 guard 地址由 `patch_wechat.py` 编译时注入 `-DIS_REVOKE_MSG_GUARD_VA=...`
- binary patch 地址由 `patch_wechat.py` 在当前 arm64 slice 中自动定位

## NEVER

- 在未验证 `patch_wechat.py` 自动解析结果前手改地址。
- 在不确认 WeChat 版本大致仍属于 4.1.8 分支的前提下执行注入。

## Verification

1. Build 无 warning：`clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c`
2. 启动后日志出现 `[antirevoke] guard set` 表示 hook 生效
3. 发送消息后对方撤回，消息应仍然可见
