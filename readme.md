# anti-revoke

**EN** | [中文](#中文)

WeChat macOS plugin that silently blocks message revocation — revoked messages remain visible in chat history without any UI marker.

> Validated on WeChat **4.1.8** series, Apple Silicon (arm64). The patch script auto-resolves the current `wechat.dylib` guard/patch addresses at install time.

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
At runtime, the hook dylib writes `hook_isRevokeMessage` into the resolved guard variable. The hook returns `0` (false), keeping the original message intact. `patch_wechat.py` now discovers the patch site and guard address directly from the installed `wechat.dylib`, then compiles the hook with that resolved guard VA.

**macOS self-revoke handling**  
macOS-initiated self-revokes arrive as two packets: a normal packet followed by a malformed one (`sender=""`, `msgid=0`). The hook uses a `mach_absolute_time` window to detect this pair and passes them through to avoid a SIGSEGV (downstream code expects a revoke result object when the function returns true).

---

## Requirements

- macOS, Apple Silicon
- WeChat 4.1.8 on Apple Silicon
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

Re-run `--backup`. The installer will auto-resolve the current `isRevokeMessage` stub and guard address from the updated `wechat.dylib`. If resolution fails, the script aborts instead of patching the wrong location.

---

## Build from Source

```bash
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
```

`patch_wechat.py` compiles and installs the dylib automatically, and also injects the resolved `IS_REVOKE_MSG_GUARD_VA` define for your installed WeChat build. Manual build is only recommended for development after resolving that guard address yourself.

---

## Limitations

- **macOS self-revoke**: Messages you revoke from the Mac client are not blocked (passthrough to avoid crash). Self-revokes initiated from the mobile client are blocked.
- **Still structure-dependent**: The installer no longer depends on one hardcoded build, but it still assumes WeChat 4.1.8's `isRevokeMessage` stub pattern and message layout. Larger client changes can still break the hook.
- **Ad-hoc codesign**: The patched app bundle is re-signed with `-`, which may trigger Gatekeeper warnings.

---

## Address Resolution

`patch_wechat.py` resolves these from the currently installed `wechat.dylib`:

- `isRevokeMessage` binary patch site
- `isRevokeMessage` guard variable

---

<br>

---

# 中文

微信 macOS 防撤回插件：静默拦截消息撤回，原消息在聊天记录中持续可见，不做“已撤回消息”标注。

> 适配微信 **4.1.8** 系列，Apple Silicon（arm64）。安装脚本会在执行时自动解析当前 `wechat.dylib` 的 patch / guard 地址。

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
Hook dylib 在运行时将 `hook_isRevokeMessage` 写入解析得到的 guard variable，hook 返回 `0`（false），消息得以保留。`patch_wechat.py` 会从当前安装的 `wechat.dylib` 中自动解析 patch 位置和 guard 地址，并用该地址编译 hook。

**macOS 端自撤回处理**  
macOS 端自撤回会产生两个数据包：一个正常包 + 一个空包（`sender=""`，`msgid=0`）。Hook 使用 `mach_absolute_time` 时间窗口识别此配对并放行，避免下游代码因缺少撤回结果对象而 SIGSEGV。

---

## 环境要求

- macOS，Apple Silicon
- 微信 4.1.8，Apple Silicon
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

重新执行 `--backup`。脚本会自动从更新后的 `wechat.dylib` 中重新解析 `isRevokeMessage` 与 guard 地址；若解析失败，会直接中止，避免 patch 错位置。

---

## 从源码构建

```bash
clang -dynamiclib -arch arm64 -o antirevoke.dylib antirevoke.c
```

`patch_wechat.py` 会自动编译安装，并把当前微信版本解析出的 `IS_REVOKE_MSG_GUARD_VA` 通过编译参数注入。除非你已经自行解析出 guard 地址，否则不建议手动直接编译。

---

## 已知限制

- **macOS 端自撤回**：从 Mac 端撤回的消息不拦截（放行以避免崩溃）；从手机端发起的自撤回正常拦截。
- **仍然依赖结构稳定**：脚本不再硬编码单一 build 地址，但仍依赖 4.1.8 这条分支里的 `isRevokeMessage` stub 模式和消息结构。若微信内部结构大改，仍需继续适配。
- **Ad-hoc 重签名**：patch 后使用 `-` 签名，可能触发 Gatekeeper 警告。

---

## 地址解析

`patch_wechat.py` 会从当前安装的 `wechat.dylib` 自动解析：

- `isRevokeMessage` 二进制 patch 位置
- `isRevokeMessage` guard variable 地址
