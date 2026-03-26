# WeChat Anti-Revoke for macOS (build 36603)
项目在线git：https://github.com/MilburnChan/anti-revoke.git

## 当前状态

| 功能 | 状态 | 说明 |
|------|------|------|
| 防撤回 | ✅ 稳定 | 原消息保留，无撤回通知 |
| 撤回标注 | ✅ 稳定 | 黄色横幅显示在聊天窗口底部，8秒后消失 |

**标注效果**：撤回发生时，WeChat 窗口底部出现黄色横幅，显示自定义文字（当前：`𝟚𝕏𝟚𝕃 𝚌𝚊𝚕𝚕𝚒𝚗𝚐 𝙲𝚀`），8 秒后自动消失。原消息始终保留在聊天记录中。

---

## 使用方法

```bash
# 先关闭微信
sudo python3 patch_wechat.py --backup    # 备份+patch+编译+安装+重签名
sudo python3 patch_wechat.py --restore   # 还原原版
python3 patch_wechat.py --dry-run        # 仅验证，不修改
```

调试日志：`/tmp/antirevoke_<pid>.log`
撤回 ID 持久化：`/tmp/antirevoke_revoked.txt`

---

## 实现原理

### 三层防守

**Layer 1 — 二进制 patch（fallback）**
- 位置：wechat.dylib VA `0x4294e2c`（isRevokeMessage 函数体 impl_start）
- 原指令：`ldr w8,[x0,#0xc]; mov w9,#0x2712; cmp w8,w9; cset w0,eq; ret`
- Patch 后：`mov w0,#0; ret`（始终返回 false）
- 作用：dylib 加载前的安全网

**Layer 2 — Guard variable hook（主路径）**
- isRevokeMessage guard VA：`0x8f8b2a8`
- 运行时写入 hook 函数指针，优先于 binary patch 执行
- hook 返回 0（false）→ call site 2 进入 false path → 原消息保留
- hook 同时解析撤回 XML，记录被撤回消息的 ID（`<newmsgid>` 和 `<msgid>`）

**Layer 3 — ObjC contentView 注入（UI 标注）**
- 撤回检测到时，通过 `dispatch_async_f` 在主线程执行
- 用 ObjC runtime 获取 `[NSApplication sharedApplication].keyWindow.contentView`
- 创建 `NSTextField`（黄底黑字，全宽，28px 高）注入到 contentView 最上层
- 8 秒后自动 `removeFromSuperview`
- 不依赖系统通知，不做 ObjC 类枚举，不会崩溃

### Guard variable 机制

wechat.dylib 大量函数使用此模式：
```asm
adrp x9, <guard_page>
ldr  x9, [x9, <guard_offset>]   ; 从 __DATA 加载函数指针
cbz  x9, <impl_start>           ; NULL → 执行原始实现（binary patch 在这里）
br   x9                          ; 非 NULL → 跳到 hook
```
guard variable 在 `__DATA` 段，运行时可写。

---

## 消息撤回流程

### isRevokeMessage 唯一有效调用点

**Call site 2** @ VA `0x44d1ca0`（函数 `0x44d1b0c`，1136B）：
```asm
0x44d1ca0: bl   0x4294e1c       ; isRevokeMessage?
0x44d1ca4: cbz  w0, 0x44d1db4   ; false → false path（原消息保留，无通知）
0x44d1ca8: ...                  ; true  → 创建 704B revoke action 对象
```
Call site 1（VA `0x261d7e8`）**从未被触发**。

---

## 消息对象结构（运行时 dump，type 10002）

| 偏移 | 类型 | 内容 | 说明 |
|------|------|------|------|
| +0x0c | int32 | 10002 | 消息类型 |
| +0x18 | SSO string | "wxid_xxx" | 发送者 ID |
| +0x30 | SSO string | "wxid_xxx" | 聊天 ID |
| +0x138 | SSO string | `<sysmsg type="revokemsg">...` | 撤回 XML |

撤回 XML 含：`<session>`, `<msgid>`, `<newmsgid>`, `<replacemsg>`

SSO string（libc++ ARM64）：短串 inline（≤22B），长串 ptr+size+cap（byte[23] 高位置1）

---

## UI 架构说明

WeChat macOS 使用**混合 C++/ObjC/Qt**架构：
- **C++ 层（核心）**：`mmui::` 命名空间，聊天渲染类（`ChatTextItemView` 等）**不在 ObjC runtime 中注册**，无法通过 `objc_getClassList` 找到
- **ObjC 桥接层**：AppKit 窗口（`NSWindow`/`NSView`）可通过 ObjC runtime 访问
- **已验证**：无任何微信自有 ObjC 类实现 `setMessage:`，ObjC swizzle 路线不可行

**Layer 3 的实现选择**：直接向 `keyWindow.contentView` 注入 `NSTextField`，绕过对微信内部渲染类的依赖。

---

## 已测试但排除的方案

| 方案 | 结果 |
|------|------|
| ObjC swizzle `setMessage:` | ❌ 无微信自有类，全是系统类（RPLegacySessionMessage 等） |
| ObjC 类枚举（constructor 阶段） | ❌ 触发未初始化类的 `+initialize`，微信崩溃 |
| ObjC 类枚举（dispatch 到主线程） | ❌ 仍崩溃，原因未完全定位 |
| `NSWindow setSubtitle:` | ❌ 微信自定义 titlebar，subtitle 不显示 |
| BL[16] → 0x40feaa4 / BL[5] → 0x40fb210 | ❌ 非删除点，返回0→消息删除+通知保留 |

---

## 撤回 handler 关键 BL（参考）

revoke action vtable[6] = `0x44e9e58` → handler `0x40f8378`（3540B，96 BLs）

| BL | VA | Guard VA | 说明 |
|----|-----|----------|------|
| BL[11] | `0x5f3f040` | `0x86f0860` | WCDB写，疑似 UPDATE 原消息 |
| BL[13] | `0x5f3f160` | `0x8aea220` | WCDB写，疑似删除 |
| BL[15] | `0x5f3ef98` | `0x8aea130` | WCDB写，疑似删除 |
| BL[17] | `0x5f3f040` | — | WCDB写，疑似写通知记录 |
| BL[22] | `0x3f41700` | `0x8f5fd40` | 通知插入（确认） |

---

## Key Addresses (build 36603)

| Symbol | VA |
|--------|----|
| `IS_REVOKE_MSG_GUARD_VA` | `0x8f8b2a8` |
| binary patch | `0x4294e2c` |
| isSystemMessage | `0x4291990`（guard `0x8f8afe0`） |

---

## wechat.dylib 结构

```
FAT binary (308MB):
  x86_64: offset=0x4000
  arm64:  offset=0x97C8000, size=0x8e39a70

arm64 slice:
  __TEXT:       vmaddr=0x0        vmsize=0x86F0000
    __text:    addr=0x16000      size=0x5F25DD0  (338,185 函数)
    __cstring: addr=0x842FB8D    size=0xF7080
  __DATA_CONST: vmaddr=0x86F0000
  __DATA:       vmaddr=0x8AE8000                 (guard variable 在此)
  __LINKEDIT:   vmaddr=0x9020000
```

VA 到文件偏移：`file_offset = 0x97C8000 + VA`（__TEXT fileoff=0）

---

## 分析脚本

| 脚本 | 用途 |
|------|------|
| `patch_wechat.py` | 主工具：binary patch + dylib 编译安装 + LC_LOAD_DYLIB + 重签名 |
| `analyze_handler.py` | 分析 revoke handler 的 96 个 BL 调用，输出 guard VA 列表 |
| `find_wcdb_funcs.py` | 通过 __cstring 字符串定位 WCDB 函数 |

---

## 构建命令

```bash
clang -dynamiclib -arch arm64 -framework Foundation -lobjc \
      -o antirevoke.dylib antirevoke.c
```

---

## 注意事项

- WeChat 版本：4.1.8.29（build 36603），更新后地址可能变化
- 需要 `sudo` 写入 `/Applications/WeChat.app`
- ad-hoc 重签名后 Gatekeeper 可能弹警告
- patch 后每次微信自动更新都需要重新执行 `--backup`
