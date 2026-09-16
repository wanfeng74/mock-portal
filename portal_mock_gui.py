# -*- coding: utf-8 -*-
"""
模拟 Panabit Portal 服务器 —— 可视化界面 (tkinter, 零第三方依赖)。

功能:
  - 启动/停止模拟 Portal API 服务器 (端口可改)
  - 劫持模式: 监听 80 (HTTP 302) + 53 (DNS) —— 模拟"连上热点即被认证页拦截"
  - 测试账号管理 (增/删, 密码明文存于内存, 仅本机调试用)
  - 在线设备列表实时显示
  - 请求日志实时滚动

打包成 EXE (Windows 上执行一次):
    pip install pyinstaller
    pyinstaller --onefile --windowed --name PanabitPortalMock portal_mock_gui.py
"""

import queue
import socket
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

from mock_server import PortalServer

BG = '#1e1e1e'
FG = '#e0e0e0'
ACCENT = '#2f7bd9'
PANEL = '#2a2a2a'
BORDER = '#3a3a3a'


class MockPortalGui:
    def __init__(self, root):
        self.root = root
        root.title('模拟 Panabit Portal 服务器 (wifi-login 调试工具)')
        root.geometry('920x680')
        root.minsize(800, 600)
        root.configure(bg=BG)

        self.log_q = queue.Queue()
        self.devices_q = queue.Queue()
        self.server = None
        self.running = False
        self.hijack_on = tk.BooleanVar(value=False)
        self.strict_on = tk.BooleanVar(value=False)
        self.strict_applied = False

        self._build_ui()
        self._tick()  # 日志轮询
        root.protocol('WM_DELETE_WINDOW', self._on_close)

    # ------------------------------------------------------------ UI 构建
    def _build_ui(self):
        # 顶栏
        head = tk.Frame(self.root, bg=BG)
        head.pack(fill='x', padx=12, pady=(10, 6))
        tk.Label(head, text='模拟 Panabit Portal 服务器', bg=BG, fg='white',
                 font=('Microsoft YaHei', 15, 'bold')).pack(side='left')
        self.state_label = tk.Label(head, text='● 未启动', bg=BG, fg='#888888',
                                    font=('Microsoft YaHei', 11, 'bold'))
        self.state_label.pack(side='right')

        # 服务器控制
        ctl = tk.Frame(self.root, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        ctl.pack(fill='x', padx=12, pady=4)
        tk.Label(ctl, text='监听端口', bg=PANEL, fg=FG).grid(row=0, column=0, padx=(14, 6), pady=10, sticky='w')
        self.port_var = tk.StringVar(value='8080')
        tk.Entry(ctl, textvariable=self.port_var, width=8, bg='#1a1a1a', fg='white',
                 insertbackground='white', relief='flat').grid(row=0, column=1, padx=6, pady=10)
        self.btn_start = tk.Button(ctl, text='启 动', command=self.start_server, bg=ACCENT, fg='white',
                                   width=8, relief='flat', activebackground='#3a8ae0', activeforeground='white')
        self.btn_start.grid(row=0, column=2, padx=6, pady=10)
        self.btn_stop = tk.Button(ctl, text='停 止', command=self.stop_server, bg='#4a4a4a', fg='white',
                                  width=8, relief='flat', state='disabled', activebackground='#5a5a5a')
        self.btn_stop.grid(row=0, column=3, padx=6, pady=10)
        tk.Checkbutton(ctl, text='劫持模式 (80+DNS53, 需管理员)', variable=self.hijack_on,
                       bg=PANEL, fg=FG, selectcolor=PANEL, activebackground=PANEL,
                       activeforeground=FG).grid(row=0, column=4, padx=14, pady=10)
        tk.Label(ctl, text='本机IP:', bg=PANEL, fg=FG).grid(row=0, column=5, padx=(10, 4), pady=10)
        self.ip_label = tk.Label(ctl, text=self._lan_ip(), bg=PANEL, fg='#37c2a0')
        self.ip_label.grid(row=0, column=6, padx=4, pady=10, sticky='w')
        tk.Button(ctl, text='刷新', command=self._refresh_ip, bg='#3a3a3a', fg=FG,
                  relief='flat', width=5).grid(row=0, column=7, padx=(4, 14), pady=10)

        # 严格拦截行 (防火墙层兜底: 未认证前物理上不放行任何外网流量)
        strict_row = tk.Frame(ctl, bg=PANEL)
        strict_row.grid(row=1, column=0, columnspan=8, sticky='w', padx=14, pady=(0, 10))
        tk.Checkbutton(strict_row, text='严格拦截 (认证前不放行任何请求, 需管理员)', variable=self.strict_on,
                       bg=PANEL, fg=FG, selectcolor=PANEL, activebackground=PANEL,
                       activeforeground=FG).pack(side='left')
        tk.Label(strict_row, text='热点网卡:', bg=PANEL, fg=FG).pack(side='left', padx=(12, 4))
        self.iface_var = tk.StringVar(value='')
        tk.Entry(strict_row, textvariable=self.iface_var, width=26, bg='#1a1a1a', fg='white',
                 insertbackground='white', relief='flat').pack(side='left', padx=4)
        tk.Button(strict_row, text='探测', command=self.detect_iface, bg='#3a3a3a', fg=FG,
                  relief='flat', width=5).pack(side='left', padx=4)

        # 中部: 账号 + 设备
        mid = tk.Frame(self.root, bg=BG)
        mid.pack(fill='both', expand=True, padx=12, pady=4)

        # 账号面板
        acc = tk.Frame(mid, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        acc.pack(side='left', fill='both', expand=True, padx=(0, 6))
        tk.Label(acc, text='测试账号', bg=PANEL, fg=FG, font=('Microsoft YaHei', 11, 'bold')
                 ).pack(anchor='w', padx=12, pady=(10, 4))
        self.acc_list = tk.Listbox(acc, bg='#1a1a1a', fg=FG, relief='flat', height=6,
                                   selectbackground=ACCENT, highlightthickness=0)
        self.acc_list.pack(fill='both', expand=True, padx=12, pady=4)
        acc_row = tk.Frame(acc, bg=PANEL)
        acc_row.pack(fill='x', padx=12, pady=(4, 10))
        self.acc_user = tk.Entry(acc_row, width=10, bg='#1a1a1a', fg='white', insertbackground='white', relief='flat')
        self.acc_user.pack(side='left', padx=(0, 6))
        self.acc_pass = tk.Entry(acc_row, width=10, bg='#1a1a1a', fg='white', insertbackground='white', relief='flat')
        self.acc_pass.pack(side='left', padx=(0, 6))
        tk.Button(acc_row, text='添加', command=self.add_account, bg=ACCENT, fg='white',
                  relief='flat', width=5).pack(side='left', padx=(0, 6))
        tk.Button(acc_row, text='删除', command=self.del_account, bg='#7a2f2f', fg='white',
                  relief='flat', width=5).pack(side='left')

        # 设备面板
        dev = tk.Frame(mid, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        dev.pack(side='left', fill='both', expand=True, padx=(6, 0))
        dev_head = tk.Frame(dev, bg=PANEL)
        dev_head.pack(fill='x', padx=12, pady=(10, 4))
        tk.Label(dev_head, text='在线设备', bg=PANEL, fg=FG, font=('Microsoft YaHei', 11, 'bold')
                 ).pack(side='left')
        tk.Button(dev_head, text='全部下线', command=self.off_all, bg='#7a2f2f', fg='white',
                  relief='flat', width=8).pack(side='right')
        cols = ('name', 'ip', 'mac', 'birth')
        self.dev_tree = ttk.Treeview(dev, columns=cols, show='headings', height=6)
        for c, t, w in (('name', '设备名', 120), ('ip', 'IP', 110), ('mac', 'MAC', 140), ('birth', '上线时间', 80)):
            self.dev_tree.heading(c, text=t)
            self.dev_tree.column(c, width=w, anchor='w')
        self.dev_tree.pack(fill='both', expand=True, padx=12, pady=4)
        self.dev_count = tk.Label(dev, text='在线 0 台', bg=PANEL, fg='#37c2a0')
        self.dev_count.pack(anchor='w', padx=12, pady=(0, 8))

        # 日志
        log_panel = tk.Frame(self.root, bg=PANEL, highlightthickness=1, highlightbackground=BORDER)
        log_panel.pack(fill='both', expand=True, padx=12, pady=4)
        tk.Label(log_panel, text='请求日志', bg=PANEL, fg=FG, font=('Microsoft YaHei', 11, 'bold')
                 ).pack(anchor='w', padx=12, pady=(8, 4))
        self.log_text = tk.Text(log_panel, bg='#141414', fg='#cccccc', relief='flat', font=('Consolas', 9),
                                height=10, state='disabled')
        sb = tk.Scrollbar(log_panel, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=sb.set)
        sb.pack(side='right', fill='y', padx=(0, 8), pady=(0, 8))
        self.log_text.pack(fill='both', expand=True, padx=(12, 0), pady=(0, 8))

        # 状态栏
        status = tk.Frame(self.root, bg=BG)
        status.pack(fill='x', padx=12, pady=(2, 8))
        self.status_var = tk.StringVar(value='就绪: 启动服务器后, 词典笔用 外部调用 或 DBG 开关连接本机')
        tk.Label(status, textvariable=self.status_var, bg=BG, fg='#888888',
                 font=('Microsoft YaHei', 9)).pack(side='left')

        self._load_accounts()

    # ------------------------------------------------------------ 账号
    def _load_accounts(self):
        self.acc_list.delete(0, 'end')
        accs = self.server.accounts if self.server else {'admin': '123456', 'test': '888888'}
        for u, p in accs.items():
            self.acc_list.insert('end', '%s / %s' % (u, p))

    def add_account(self):
        u = self.acc_user.get().strip()
        p = self.acc_pass.get().strip()
        if not u or not p:
            messagebox.showwarning('提示', '请输入账号和密码')
            return
        if self.server:
            self.server.accounts[u] = p
            self.append_log('[账号] 添加 %s' % u)
        else:
            messagebox.showinfo('提示', '服务器未启动, 账号将在启动后生效 (可先启动再添加)')
            return
        self.acc_user.delete(0, 'end')
        self.acc_pass.delete(0, 'end')
        self._load_accounts()

    def del_account(self):
        sel = self.acc_list.curselection()
        if not sel:
            return
        line = self.acc_list.get(sel[0])
        u = line.split(' / ')[0]
        if self.server and u in self.server.accounts:
            del self.server.accounts[u]
            self.append_log('[账号] 删除 %s' % u)
        self._load_accounts()

    # ------------------------------------------------------------ 设备
    def off_all(self):
        if self.server:
            self.server.sessions.clear()
            self.server.online = []
            self._refresh_devices([])
            self.append_log('[设备] 全部下线')

    def _refresh_devices(self, devices):
        self.dev_tree.delete(*self.dev_tree.get_children())
        for d in devices:
            self.dev_tree.insert('', 'end', values=(d.get('name', ''), d.get('ipstr', ''),
                                                    d.get('clntmac', ''), d.get('birth', '')))
        self.dev_count.config(text='在线 %d 台' % len(devices))

    # ------------------------------------------------------------ 严格拦截
    def detect_iface(self):
        from mock_server import list_hotspot_interfaces
        names = list_hotspot_interfaces()
        if not names:
            self.append_log('[严格] 未探测到已连接网卡 (非 Windows 或无 PowerShell)')
            self.append_log('[严格] 请手动输入热点网卡名, 例如: vEthernet (WLAN)')
            return
        pick = names[0]
        for n in names:
            if 'vEthernet' in n or 'WLAN' in n:
                pick = n
                break
        self.iface_var.set(pick)
        self.append_log('[严格] 已探测网卡: %s' % pick)

    # ------------------------------------------------------------ 服务器
    def start_server(self):
        if self.running:
            return
        try:
            port = int(self.port_var.get())
        except ValueError:
            messagebox.showerror('错误', '端口必须是数字')
            return
        if not (1 <= port <= 65535):
            messagebox.showerror('错误', '端口范围 1-65535')
            return
        self.server = PortalServer(port=port, on_log=self.append_log)
        # 设备表更新必须回 UI 线程 (服务器线程只往队列放, 由 _tick 在主线程处理)
        self.server.on_devices = lambda devs: self.devices_q.put(devs)
        try:
            self.server.start(hijack=self.hijack_on.get(), pc_ip=self._lan_ip())
        except OSError as e:
            messagebox.showerror('启动失败', '端口 %d 被占用: %s\n请换一个端口' % (port, e))
            self.server = None
            return
        self.running = True
        # 严格拦截: 与劫持模式配合, 在热点网卡上封掉 80/53 之外的所有入站流量
        self.strict_applied = False
        if self.strict_on.get():
            if not self.hijack_on.get():
                self.append_log('[严格] 严格拦截需与劫持模式一起开启, 本次未启用')
            else:
                from mock_server import apply_firewall_policy
                iface = self.iface_var.get().strip()
                if iface:
                    self.strict_applied = apply_firewall_policy(iface, True, on_log=self.append_log)
                    if not self.strict_applied:
                        messagebox.showwarning(
                            '严格拦截未生效',
                            '防火墙规则添加失败，详见日志。\n'
                            '常见原因：\n'
                            '1. 未以管理员身份运行（EXE 会弹 UAC 提权，请点"是"）\n'
                            '2. 热点网卡名不正确（点"探测"自动获取，或对照"网络连接"面板）')
                else:
                    self.append_log('[严格] 未填写热点网卡 (可点"探测"自动获取), 严格拦截未启用')
        self._set_state(True)
        self._load_accounts()
        self._refresh_devices(self.server.online)
        self.status_var.set('运行中: API 地址 http://%s:%d/api   (劫持: %s)' %
                            (self._lan_ip(), port, '开' if self.hijack_on.get() else '关'))
        self.append_log('=== 服务器已启动, 端口 %d ===' % port)

    def stop_server(self):
        if self.server:
            self.server.stop()
        # 移除严格拦截防火墙规则, 恢复放行
        if self.strict_applied:
            from mock_server import apply_firewall_policy
            apply_firewall_policy(self.iface_var.get().strip(), False, on_log=self.append_log)
            self.strict_applied = False
        self.running = False
        self._set_state(False)
        self.status_var.set('已停止')
        self.append_log('=== 服务器已停止 ===')

    def _set_state(self, running):
        self.state_label.config(text='● 运行中' if running else '● 未启动',
                                fg='#37c2a0' if running else '#888888')
        self.btn_start.config(state='disabled' if running else 'normal')
        self.btn_stop.config(state='normal' if running else 'disabled')

    # ------------------------------------------------------------ 工具
    def _lan_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('223.5.5.5', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'

    def _refresh_ip(self):
        self.ip_label.config(text=self._lan_ip())

    def append_log(self, line):
        self.log_q.put(line)

    def _tick(self):
        try:
            while True:
                line = self.log_q.get_nowait()
                self.log_text.config(state='normal')
                self.log_text.insert('end', '[%s] %s\n' % (time.strftime('%H:%M:%S'), line))
                self.log_text.see('end')
                self.log_text.config(state='disabled')
        except queue.Empty:
            pass
        try:
            while True:
                devs = self.devices_q.get_nowait()
                self._refresh_devices(devs)
        except queue.Empty:
            pass
        self.root.after(200, self._tick)

    def _on_close(self):
        if self.running:
            self.stop_server()
        self.root.destroy()


def main():
    root = tk.Tk()
    try:
        ttk.Style().theme_use('clam')
    except Exception:
        pass
    MockPortalGui(root)
    root.mainloop()


if __name__ == '__main__':
    main()
