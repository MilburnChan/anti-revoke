# anti-revoke

**EN** | [中文](#中文)

WeChat macOS plugin that silently blocks message revocation — revoked messages remain visible in chat history without any notification or UI change.

> Tested on WeChat **4.1.8 (build 36603)**, Apple Silicon (arm64).

---

## How It Works

Two-layer defense against `isRevokeMessage`:

**Layer 1 — Binary patch (fallback)**  
Patches `wechat.dylib` at VA `0x4294e2c` to replace the `isRevokeMessage` impl with `mov w0, #0; ret`, ensuring the function always returns false even before the hook dylib loads.

**Layer 2 — Guard variable hook (primary)**  
WeChat's dylib functions use a common indirect-call pattern:
```asm
ldr  x9, [guard_va]   ; load fn ptr from __DATA
cbz  x9, impl_start   ; NULL → fall through to binary (Layer 1)
br   x9               ; non-NULL → jump to hook
```
At runtime, the hook dylib writes `hook_isRevokeMessage` into the guard variable at `0x8f8b2a8`. The hook returns `0` (false), keeping the original message intact. It also parses the revoke XML to record revoked message IDs for persistence.

**macOS self-revoke handling**  
macOS-initiated self-revokes arrive as two packets: a normal packet followed by a malformed one (`sender=""`, `msgid=0`). The hook uses a `mach_absolute_time` window to detect this pair and passes them through to avoid a SIGSEGV (downstream code expects a revoke result object when the function returns true).

---

## Requirements

- macOS, Apple Silicon
- WeChat 4.1.8 (build 36603) — other builds untested
- Xcode Command Line Tools (`clang`)
- `sudo` access

---

## Install

```bash
git clone https://github.com/MilburnChan/anti-revoke.git
cd anti-revoke
sudo python3 patch_wechat.py --backup
```

Quit WeChat before running. `--backup` creates `wechat.dylib.bak` before modifying. Restart WeChat after.

## Uninstall

```bash
sudo python3 patch_wechat.py --restore
```

## After WeChat Updates

Re-run `--backup`. If the build number changed, byte verification of the binary patch will fail and the script aborts — wait for a compatibility update.

---

## Build from Source

```bash
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
```

`patch_wechat.py` compiles and installs the dylib automatically; manual build is only needed for development.

---

## Limitations

- **macOS self-revoke**: Messages you revoke from the Mac client are not blocked (passthrough to avoid crash). Self-revokes initiated from the mobile client are blocked.
- **Version-locked**: All addresses are hardcoded for build 36603. WeChat updates will break the hook.
- **Ad-hoc codesign**: The patched app bundle is re-signed with `-`, which may trigger Gatekeeper warnings.

---

## Key Addresses (build 36603)

| Symbol | Virtual Address |
|--------|----------------|
| `isRevokeMessage` guard | `0x8f8b2a8` |
| Binary patch site | `0x4294e2c` |
| Active call site | `0x44d1ca0` |

---

<br>

---

# 中文

微信 macOS 防撤回插件 — 静默拦截消息撤回，原消息在聊天记录中持续可见，无通知、无视觉变化。

> 适配微信 **4.1.8（build 36603）**，Apple Silicon（arm64）。

---

## 实现原理

针对 `isRevokeMessage` 的双层防御：

**Layer 1 — 二进制 patch（兜底）**  
在 `wechat.dylib` VA `0x4294e2c` 处将 `isRevokeMessage` 的函数体 patch 为 `mov w0, #0; ret`，使其在 hook dylib 加载前即返回 false。

**Layer 2 — Guard variable hook（主路径）**  
微信 dylib 的大量函数采用间接调用模式：
```asm
ldr  x9, [guard_va]   ; 从 __DATA 加载函数指针
cbz  x9, impl_start   ; NULL → 走 binary patch（Layer 1）
br   x9               ; 非 NULL → 跳到 hook
```
Hook dylib 在运行时将 `hook_isRevokeMessage` 写入 `0x8f8b2a8` 处的 guard variable，hook 返回 `0`（false），消息得以保留。同时解析撤回 XML，持久化记录被撤回消息的 ID。

**macOS 端自撤回处理**  
macOS 端自撤回会产生两个数据包：一个正常包 + 一个空包（`sender=""`，`msgid=0`）。Hook 使用 `mach_absolute_time` 时间窗口识别此配对并放行，避免下游代码因缺少撤回结果对象而 SIGSEGV。

---

## 环境要求

- macOS，Apple Silicon
- 微信 4.1.8（build 36603）— 其他版本未测试
- Xcode Command Line Tools（提供 `clang`）
- `sudo` 权限

---

## 安装

```bash
git clone https://github.com/MilburnChan/anti-revoke.git
cd anti-revoke
sudo python3 patch_wechat.py --backup
```

运行前需退出微信。`--backup` 会在修改前备份 `wechat.dylib`。完成后重启微信生效。

## 卸载

```bash
sudo python3 patch_wechat.py --restore
```

## 微信更新后

重新执行 `--backup`。若 build 号变更，脚本会因 patch 字节校验失败而中止 — 等待适配新版本。

---

## 从源码构建

```bash
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
```

`patch_wechat.py` 会自动编译安装，仅开发时需手动构建。

---

## 已知限制

- **macOS 端自撤回**：从 Mac 端撤回的消息不拦截（放行以避免崩溃）；从手机端发起的自撤回正常拦截。
- **版本绑定**：所有地址硬编码于 build 36603，微信更新后 hook 失效。
- **Ad-hoc 重签名**：patch 后使用 `-` 签名，可能触发 Gatekeeper 警告。

---

## 关键地址（build 36603）

| 符号 | 虚拟地址 |
|------|---------|
| `isRevokeMessage` guard | `0x8f8b2a8` |
| 二进制 patch 位置 | `0x4294e2c` |
| 有效调用点 | `0x44d1ca0` |
