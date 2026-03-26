# WeChat Anti-Revoke for macOS (build 36603)
项目在线git：https://github.com/MilburnChan/anti-revoke.git

## 当前状态

| 功能 | 状态 | 说明 |
|------|------|------|
| 防撤回 | ✅ 稳定 | 原消息保留，无撤回通知 |
| 撤回标注（窗口 banner） | ✅ 稳定 | 黄色横幅显示在聊天窗口底部，8秒后消失 |
| 撤回标注（气泡着色） | 🔬 未来方向 | 直接修改被撤回消息的气泡颜色/字体，见下方开发路线图 |

**当前标注效果**：撤回发生时，WeChat 窗口底部出现黄色横幅，显示自定义文字（当前：`𝟚𝕏𝟚𝕃 𝚌𝚊𝚕𝚕𝚒𝚗𝚐 𝙲𝚀`），8 秒后自动消失。原消息始终保留在聊天记录中。

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

## 未来开发方向：气泡着色（C++ vtable hook）

> **结论：可解决，原理上与找到 `isRevokeMessage` 属于同一难度量级。**
> 当初 `isRevokeMessage` 也是在 338,185 个函数里从零定位的，本项目已有完整的工具链和方法论。

### 目标效果

被撤回的消息气泡同时实现两处变化，无论用户何时回到屏幕都能一眼识别，不依赖临时 banner：

1. **气泡着色**：改变气泡背景色或字体颜色（如红色边框、灰化）
2. **文字标注**：在气泡内容末尾追加 `𝟚𝕏𝟚𝕃 𝚌𝚊𝚕𝚕𝚒𝚗𝚐 𝙲𝚀`

两者都在同一个渲染 hook 里完成——找到渲染方法后，既可以修改颜色字段，也可以在输出文字时追加自定义字符串，工作量不会因此翻倍。

### 技术路线

WeChat macOS 的聊天渲染层是纯 C++ + Qt（已确认：无 ObjC 类可 swizzle）。实现气泡着色需要以下步骤：

**Step 1：定位 `mmui::ChatBubbleItemView`（或 `ChatTextItemView`）的 vtable**

- 在 wechat.dylib `__cstring` 段搜索 `"ChatBubbleItemView"` 或 `"ChatTextItemView"` 字符串
- 用 ADRP+ADD 链分析找到引用该字符串的代码位置（即类注册或 RTTI 数据）
- 从 RTTI/type_info 结构推导出 vtable 地址
- 工具：capstone 反汇编 + 现有 `analyze_handler.py` 框架

**Step 2：识别"绘制单条消息"的虚方法**

- vtable 里按 index 逐一分析，找到参数中含消息对象指针的 draw 方法
- 参考已知的 `OnMessageRevoke`、`UpdateBubbleData`、`drawRect:` 等入口
- 可通过在 vtable 各 slot 设置 guard hook，观察调用时机来定位

**Step 3：在 hook 里识别当前渲染的消息**

- C++ 消息对象的 `this` 指针作为第一个参数传入渲染方法
- 找到消息 ID 字段在 C++ 对象内的偏移（参考 type 10002 消息对象已知的 SSO string 偏移分析方法）
- 对比 `g_revoked[]` 集合，判断是否需要着色

**Step 4：修改渲染颜色并处理 cell 复用**

- 在 hook 内修改 C++ 对象的颜色/样式字段，或直接修改 CALayer 属性
- Qt 的 cell 复用机制要求每次渲染时都做判断（不能一次性写死）
- 可通过修改 vtable slot 指针实现持久 hook

### 已知信息（可复用）

| 已有 | 用途 |
|------|------|
| `g_revoked[]` + 持久化文件 | 撤回消息 ID 集合，hook 可直接查询 |
| SSO string 解析 | 从 C++ 对象读取消息 ID |
| guard variable hook 机制 | 同样适用于 vtable slot hook |
| `analyze_handler.py` | capstone 反汇编框架，可复用于 vtable 分析 |
| wechat.dylib 段结构、VA→文件偏移 | 已知，直接用 |

### 预期阻力

- **C++ RTTI 可能被 strip**：如果没有类名字符串，需要从已知的 `OnMessageRevoke` 调用回溯到包含它的类
- **Qt 批量渲染**：如果整个聊天列表是一次性绘制而非逐 cell 调用，需要找更上层的 layout 方法
- **cell 复用颜色重置**：需要确保每次 cell 被重用时 hook 都重新着色

---

## 注意事项

- WeChat 版本：4.1.8.29（build 36603），更新后地址可能变化
- 需要 `sudo` 写入 `/Applications/WeChat.app`
- ad-hoc 重签名后 Gatekeeper 可能弹警告
- patch 后每次微信自动更新都需要重新执行 `--backup`
