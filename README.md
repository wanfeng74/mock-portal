# 模拟 Panabit Portal 服务器（可视化版）

在有道词典笔等设备上调试 `wifi-login`（1.1.2 适配修复版）时，**在本机模拟一个 Panabit 认证服务器**，让客户端完整跑通「登录 → 状态心跳 → 设备管理」流程，不需要真实网关。

- 纯 Python 标准库实现（tkinter + http.server + socket），**零第三方依赖**
- AES-128-ECB/ZeroPadding 与客户端 `aes.js` 完全一致（已用客户端密文闭环验证）
- 支持**劫持模式**：监听 80 端口 HTTP 302 + 53 端口 DNS，模拟「连上热点即被认证页拦截」

---

## 文件说明

| 文件 | 作用 |
|---|---|
| `portal_mock_gui.py` | **主程序**：可视化界面（启动服务器 / 劫持模式 / 账号管理 / 设备列表 / 实时日志） |
| `mock_server.py` | 模拟 Panabit API 服务器 + 劫持（HTTP 302 + DNS），无界面也可单独运行 |
| `aes128.py` | 纯 Python AES-128-ECB/ZeroPadding（与客户端 `aes.js` 一致） |
| `build_exe.bat` | **Windows 一键打包 EXE** |

## 快速开始

```sh
# 有 Python 3.8+ 直接运行（Windows / Linux / macOS 均可）
python portal_mock_gui.py

# 无界面模式（API 服务器，默认端口 8080）
python mock_server.py 8080

# 无界面模式 + 劫持（80+DNS53，Windows 需管理员）
python mock_server.py 8080 --hijack
```

界面操作：填端口 → 点「启动」→ 词典笔/浏览器连接本机 IP 即可。

## 打包成 Windows EXE（在 Windows 电脑上执行一次）

```bat
双击 build_exe.bat
```

或在命令行：

```bat
pip install pyinstaller
pyinstaller --onefile --windowed --name PanabitPortalMock portal_mock_gui.py
```

产物：`dist\PanabitPortalMock.exe`，双击即用，目标机器**不需要装 Python**。

> 说明：PyInstaller 不支持跨平台，Linux 上无法直接生成 Windows EXE，请在 Windows 上执行上面的脚本（30~60 秒完成）。

---

## 与词典笔 wifi-login 客户端对接

### 方式一：外部小程序调用（1.1.2 已支持，无需重打包）

```js
$falcon.navTo('falcon://8001865309000001/index', {
  action: 'login',
  server: '192.168.1.100:8080',   // 改成运行本工具的 PC 局域网 IP
  username: 'admin',
  password: '123456',
  auto: '1'                        // 自动提交登录
})
```

### 方式二：DBG 联调开关（改一行代码重打包客户端）

`wifi-login/ui/src/pages/index/index.vue` 第 220 行：

```js
var DBG = { server: 'http://192.168.1.100:8080', username: 'admin', password: '123456' }
```

### 方式三：浏览器直接看效果

打开 `http://<PC-IP>:8080/portal/?userip=10.10.10.100&userurl=http://example.com` 查看模拟登录页。

---

## 劫持模式（模拟完整"连上热点即被拦截"）

启用后：

1. **80 端口**：未认证客户端的任意 HTTP 请求 → `302 Location: http://<PC-IP>:8080/portal/?userip=<客户端IP>&userurl=<原URL>`
   （词典笔的连通性探测源 `connect.rom.miui.com` 等为 http 80，会被劫持）
2. **53 端口 DNS**：**未认证客户端的任何域名一律解析到本机，不放行任何网络请求**；
   认证通过的客户端才转发上游 DNS `223.5.5.5`（放行）

Windows 上**必须用管理员身份运行**（监听 80/53 端口需要权限）。
使用前提：PC 开热点（设置 → 移动热点），词典笔连接该热点（DNS 会自动指向 PC），流量经 PC 转发。

> 提醒：劫持只在本机热点/局域网调试环境使用，不要用在公共网络上。

## 已实现的 API（与 panabit.js 契约一致）

| 接口 | 返回 |
|---|---|
| `route=portal&action=load_portal_conf` | `{code:0, policy:{auth1:'panabit', scene_str}}`；IP 以 `.200` 结尾模拟 MAC 免认证 `code:200` |
| `route=webauth&action=user_login` | 密码 AES 解密校验；成功 `{code:0, stat:1}`，失败 `{code:255, INV_NAMEORPWD}` |
| `route=webauth&action=query_auth_stat` | `{code:0, stat:0/1}` |
| `route=ucenter&action=load_user_list` | 在线设备列表 |
| `route=ucenter&action=user_offone/offall` | 下线 |

测试账号默认：`admin/123456`、`test/888888`（界面里可增删）。

## 已验证

- AES 闭环：客户端 `aes.js` 生成的密文在服务端正确解密（`123456`/`888888`/中文均通过）
- 全部 10 个 API 接口返回正确
- PyInstaller 打包流程通过（生成单文件可执行程序）
- 修复了设备列表从 HTTP 线程跨线程刷新 UI 的隐患（改为队列 + UI 线程轮询）
- 界面显示效果需在 Windows 实机确认（开发沙箱无显示环境，无法启动图形界面）
