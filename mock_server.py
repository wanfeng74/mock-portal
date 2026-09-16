# -*- coding: utf-8 -*-
"""
模拟 Panabit Portal 认证服务器 (可被 GUI 调用, 也可无头运行)。

实现的 API 契约与 wifi-login 客户端 ui/src/services/portal-adapters/panabit.js 对应:
  /api?route=portal&action=load_portal_conf    -> {code:0, data:{policy:{auth1,scene_str}}}
  /api?route=webauth&action=user_login         -> {code:0, data:{stat:1}} / {code:255, msg:'INV_NAMEORPWD'}
  /api?route=webauth&action=query_auth_stat    -> {code:0, data:{stat:0|1}}
  /api?route=ucenter&action=load_user_list     -> {code:0, data:[{name,ipstr,clntmac,birth,uid}]}
  /api?route=ucenter&action=user_offone        -> {code:0}
  /api?route=ucenter&action=user_offall        -> {code:0}
  /portal/?userip=..&userurl=..                -> 模拟登录页 (浏览器查看)

劫持模式 (在 Windows 上以管理员运行, 模拟完整"连上热点即被认证页拦截"):
  - 监听 80 端口: 未认证客户端的任意 HTTP 请求 -> 302 到 http://<PC-IP>:<PORT>/portal/?userip=<客户端IP>&userurl=<原始URL>
    (词典笔的连通性探测源 connect.rom.miui.com 等为 http 80, 会被劫持)
  - 监听 53 端口 (UDP DNS): 未认证客户端的所有域名一律解析到本机, 不放行任何网络请求;
    认证通过的客户端才转发上游 DNS (223.5.5.5)
    (词典笔连 PC 热点后 DNS 指向热点 IP, 即本机)
"""

import json
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from aes128 import pa_aes_decode

# 连通性探测源域名 (客户端 detect.js)
PROBE_DOMAINS = [
    'connect.rom.miui.com',
    'wifi.vivo.com.cn',
    'connectivitycheck.platform.hicloud.com',
]
UPSTREAM_DNS = ('223.5.5.5', 53)  # 非劫持域名转发上游


class PortalServer:
    """Panabit API 模拟服务器 + 可选劫持 (80 HTTP 302 + 53 DNS)."""

    def __init__(self, port=8080, accounts=None, on_log=None):
        self.port = port
        self.accounts = dict(accounts or {'admin': '123456', 'test': '888888'})
        self.on_log = on_log or (lambda line: None)
        self.on_devices = None  # 设备表变化回调 (GUI 刷新用)
        self.lock = threading.Lock()
        self.online = [
            {'name': '词典笔-本机', 'ipstr': '10.10.10.100', 'clntmac': 'AA:BB:CC:DD:EE:01', 'birth': '12:00:01', 'uid': '1'},
            {'name': '我的手机', 'ipstr': '10.10.10.55', 'clntmac': 'AA:BB:CC:DD:EE:02', 'birth': '11:30:00', 'uid': '2'},
        ]
        self.sessions = {}  # ip -> {authed: bool}
        self.httpd = None
        self.http_thread = None
        self.dns_sock = None
        self.dns_thread = None
        self.hijack_enabled = False
        self.pc_ip = '127.0.0.1'

    # ------------------------------------------------------------ 日志/设备
    def log(self, line):
        self.on_log(line)

    def _notify_devices(self):
        cb = self.on_devices
        if cb:
            try:
                cb(list(self.online))
            except Exception:
                pass

    # ------------------------------------------------------------ HTTP 服务器
    class _Handler(BaseHTTPRequestHandler):
        server_version = 'Panabit-Mock/1.0'
        protocol_version = 'HTTP/1.1'

        def log_message(self, *args):
            pass  # 日志走 PortalServer.log

        def do_GET(self):
            self.server.portal.handle_get(self)

        def do_POST(self):
            self.do_GET()

        def do_HEAD(self):
            self.do_GET()

    def handle_get(self, handler):
        try:
            parsed = urlparse(handler.path)
            q = parse_qs(parsed.query)
            path = parsed.path
            client_ip = handler.client_address[0]

            # 劫持: 80 端口上未认证客户端的任意路径 -> 302 到 portal 跳转页 (认证后放行)
            if self.hijack_enabled and self.httpd and self.httpd.server_address[1] == 80:
                authed = self.sessions.get(client_ip, {}).get('authed', False)
                if path != '/api' and not authed:
                    target = 'http://%s:%d/portal/?userip=%s&userurl=%s' % (
                        self.pc_ip, self.port, client_ip, handler.path)
                    handler.send_response(302)
                    handler.send_header('Location', target)
                    handler.send_header('Content-Length', '0')
                    handler.end_headers()
                    self.log('[劫持] %s %s -> 302 %s' % (client_ip, handler.path, target))
                    return

            if path in ('/portal', '/portal/'):
                body = ('<html><head><title>Panabit 上网认证</title></head>'
                        '<body><h2>模拟 Panabit Portal 登录页</h2>'
                        '<p>userip=%s&nbsp; userurl=%s</p>'
                        '<p>客户端应通过 /api 接口完成认证。</p></body></html>'
                        % (q.get('userip', [''])[0], q.get('userurl', [''])[0])).encode('utf-8')
                handler.send_response(200)
                handler.send_header('Content-Type', 'text/html; charset=utf-8')
                handler.send_header('Content-Length', str(len(body)))
                handler.end_headers()
                handler.wfile.write(body)
                return

            if path == '/api':
                self.handle_api(handler, q, client_ip)
                return

            handler.send_response(404)
            handler.send_header('Content-Length', '0')
            handler.end_headers()
        except (ConnectionAbortedError, BrokenPipeError):
            pass
        except Exception as e:
            try:
                self.send_json(handler, {'code': -1, 'msg': 'server error: %s' % e, 'data': None})
            except Exception:
                pass

    def handle_api(self, handler, q, client_ip):
        route = q.get('route', [''])[0]
        action = q.get('action', [''])[0]
        ip = q.get('ip', [''])[0] or q.get('wlanuserip', [''])[0] or q.get('userip', [''])[0]

        if route == 'portal' and action == 'load_portal_conf':
            # 模拟 MAC 免认证: ip 以 .200 结尾直接放行 (可自行改规则)
            if ip.endswith('.200'):
                self.log('[conf] %s MAC 免认证放行' % ip)
                self.send_json(handler, {'code': 200, 'msg': 'MAC auth passed', 'data': None})
                return
            self.log('[conf] %s load_portal_conf auth1=panabit' % ip)
            self.send_json(handler, {'code': 0, 'msg': 'success',
                                     'data': {'policy': {'auth1': 'panabit', 'scene_str': 'test-scene'}}})
            return

        if route == 'webauth' and action == 'user_login':
            username = q.get('username', [''])[0]
            pwd_hex = q.get('password', [''])[0]
            plain = pa_aes_decode(pwd_hex)
            self.log('[login] user=%s ip=%s 解密密码=%s' % (username, ip, plain))
            with self.lock:
                if not username or self.accounts.get(username) != plain:
                    self.send_json(handler, {'code': 255, 'msg': 'INV_NAMEORPWD', 'data': None})
                    return
                self.sessions[ip or '0.0.0.0'] = {'authed': True, 'user': username}
                if ip and not any(d['ipstr'] == ip for d in self.online):
                    self.online.append({'name': username, 'ipstr': ip,
                                        'clntmac': 'AA:BB:CC:DD:EE:03', 'birth': time.strftime('%H:%M:%S'),
                                        'uid': str(int(time.time() * 1000))})
            self._notify_devices()
            self.send_json(handler, {'code': 0, 'msg': 'success', 'data': {'stat': 1}})
            return

        if route == 'webauth' and action == 'query_auth_stat':
            s = self.sessions.get(ip or '0.0.0.0')
            stat = 1 if (s and s['authed']) else 0
            self.send_json(handler, {'code': 0, 'msg': 'success', 'data': {'stat': stat}})
            return

        if route == 'ucenter' and action == 'load_user_list':
            self.send_json(handler, {'code': 0, 'msg': 'success', 'data': self.online})
            return

        if route == 'ucenter' and action == 'user_offone':
            addr = q.get('addr', [''])[0]
            with self.lock:
                self.online = [d for d in self.online if d['ipstr'] != addr]
            self._notify_devices()
            self.log('[offone] addr=%s 剩余=%d' % (addr, len(self.online)))
            self.send_json(handler, {'code': 0, 'msg': 'success', 'data': None})
            return

        if route == 'ucenter' and action == 'user_offall':
            with self.lock:
                self.online = []
                self.sessions.clear()
            self._notify_devices()
            self.log('[offall] 全部下线')
            self.send_json(handler, {'code': 0, 'msg': 'success', 'data': None})
            return

        self.send_json(handler, {'code': -1, 'msg': 'unknown %s/%s' % (route, action), 'data': None})

    def send_json(self, handler, obj):
        body = json.dumps(obj, ensure_ascii=True).encode('ascii')
        handler.send_response(200)
        handler.send_header('Content-Type', 'text/plain; charset=ascii')
        handler.send_header('Content-Length', str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    # ------------------------------------------------------------ 启动/停止
    def start(self, hijack=False, pc_ip='127.0.0.1'):
        self.pc_ip = pc_ip or '127.0.0.1'
        self.httpd = ThreadingHTTPServer(('0.0.0.0', self.port), self._Handler)
        self.httpd.portal = self
        self.http_thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.http_thread.start()
        self.log('Portal API 服务器已启动: 0.0.0.0:%d' % self.port)
        if hijack:
            self.enable_hijack()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None
        self.disable_hijack()
        self.log('服务器已停止')

    # ------------------------------------------------------------ 劫持模式
    def enable_hijack(self):
        self.hijack_enabled = True
        # 80 端口劫持 (Windows 上建议管理员运行)
        try:
            self.hijack_httpd = ThreadingHTTPServer(('0.0.0.0', 80), self._Handler)
            self.hijack_httpd.portal = self
            self.hijack_thread = threading.Thread(target=self.hijack_httpd.serve_forever, daemon=True)
            self.hijack_thread.start()
            self.log('劫持: 已监听 80 端口 (HTTP 302 重定向)')
        except Exception as e:
            self.log('劫持: 80 端口监听失败 (%s) — 请以管理员身份运行' % e)
            self.hijack_httpd = None
        # 53 端口 DNS 劫持
        try:
            self.dns_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.dns_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.dns_sock.bind(('0.0.0.0', 53))
            self.dns_thread = threading.Thread(target=self._dns_loop, daemon=True)
            self.dns_thread.start()
            self.log('劫持: 已监听 53 端口 (DNS, 探测源域名 -> %s)' % self.pc_ip)
        except Exception as e:
            self.log('劫持: 53 端口监听失败 (%s) — 请以管理员身份运行' % e)
            self.dns_sock = None

    def disable_hijack(self):
        self.hijack_enabled = False
        if getattr(self, 'hijack_httpd', None):
            try:
                self.hijack_httpd.shutdown()
                self.hijack_httpd.server_close()
            except Exception:
                pass
            self.hijack_httpd = None
        if self.dns_sock:
            try:
                self.dns_sock.close()
            except Exception:
                pass
            self.dns_sock = None
        if self.dns_thread:
            self.dns_thread = None

    # ------------------------------------------------------------ DNS 服务器
    def _dns_loop(self):
        while self.dns_sock:
            try:
                data, addr = self.dns_sock.recvfrom(512)
                threading.Thread(target=self._dns_handle, args=(data, addr), daemon=True).start()
            except OSError:
                break

    def _dns_handle(self, data, addr):
        try:
            qname, qtype, qid = _parse_dns_query(data)
            if qname is None:
                return
            client_ip = addr[0]
            # 未认证客户端的任何域名一律解析到本机 —— 不放行任何网络请求;
            # 认证通过后才转发上游 DNS (放行)
            if self.sessions.get(client_ip, {}).get('authed', False):
                up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                up.settimeout(3)
                up.sendto(data, UPSTREAM_DNS)
                up.settimeout(3)
                try:
                    resp, _ = up.recvfrom(512)
                    self.dns_sock.sendto(resp, addr)
                except socket.timeout:
                    pass
                up.close()
            else:
                resp = _build_dns_answer(qid, qname, qtype, self.pc_ip)
                self.dns_sock.sendto(resp, addr)
                self.log('[DNS] 拦截 %s -> %s (未认证, 不放行)' % (qname, self.pc_ip))
        except Exception:
            pass


def _parse_dns_query(data):
    """解析 DNS 查询, 返回 (qname 小写, qtype, qid)."""
    if len(data) < 12:
        return None, 0, 0
    qid = struct.unpack('>H', data[0:2])[0]
    idx = 12
    labels = []
    while idx < len(data):
        ln = data[idx]
        if ln == 0:
            idx += 1
            break
        if ln & 0xC0:  # 压缩指针 (查询里一般没有)
            return None, 0, 0
        idx += 1
        if idx + ln > len(data):
            return None, 0, 0
        labels.append(data[idx:idx + ln].decode('latin1'))
        idx += ln
    if idx + 4 > len(data):
        return None, 0, 0
    qtype = struct.unpack('>H', data[idx:idx + 2])[0]
    return '.'.join(labels).lower(), qtype, qid


def _build_dns_answer(qid, qname, qtype, ip):
    """构造 A 记录应答 (ip 为点分十进制)."""
    header = struct.pack('>HHHHHH', qid, 0x8180, 1, 1, 0, 0)
    question = b''
    for part in qname.split('.'):
        question += bytes([len(part)]) + part.encode('latin1')
    question += b'\x00'
    question += struct.pack('>HH', qtype, 1)
    ip_bin = socket.inet_aton(ip)
    answer = struct.pack('>HHHLH', 0xC00C, qtype, 1, 60, 4) + ip_bin
    return header + question + answer


# ------------------------------------------------------------ Windows 防火墙严格拦截
# 只劫持 80/53 仍会被 Windows 热点 NAT 放行其他流量(如 HTTPS 443),
# 严格拦截 = 在热点网卡上: 入站仅放行 TCP80/UDP53(另加 DHCP/ICMP 便于诊断),
#            其余所有 TCP/UDP 一律拦截 —— 认证前物理上无法访问外网。

FW_RULES = ['PortalMock-block-tcp', 'PortalMock-block-udp', 'PortalMock-allow-80',
            'PortalMock-allow-53', 'PortalMock-allow-dhcp', 'PortalMock-allow-icmp']


def list_hotspot_interfaces():
    """探测已连接网卡名列表 (Windows; 非 Windows 返回空列表). 优先热点网卡."""
    if sys.platform != 'win32':
        return []
    import subprocess
    try:
        out = subprocess.run(
            ['powershell', '-NoProfile', '-Command',
             "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | "
             "Sort-Object -Property Name | Select-Object -ExpandProperty Name"],
            capture_output=True, text=True, timeout=10)
        names = [ln.strip() for ln in out.stdout.splitlines() if ln.strip()]
        # 热点网卡优先
        for n in names:
            if 'vEthernet' in n or 'WLAN' in n or 'Virtual' in n:
                names.remove(n)
                names.insert(0, n)
        return names
    except Exception:
        return []


def apply_firewall_policy(interface, enable, on_log=None):
    """严格拦截开关: 热点网卡入站仅放行 TCP80/UDP53(及 DHCP/ICMP), 其余全部拦截.
    enable=True 添加规则, False 移除全部规则. 仅 Windows, 需管理员权限."""
    log = on_log or (lambda s: None)
    if sys.platform != 'win32':
        log('严格拦截: 仅 Windows 支持 (netsh 防火墙)')
        return False
    if not interface:
        log('严格拦截: 未指定热点网卡, 已跳过')
        return False
    import subprocess

    def run(cmd):
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return r.returncode, (r.stderr or r.stdout).strip()

    # 先清理旧规则, 保证可重复启停
    for name in FW_RULES:
        run('netsh advfirewall firewall delete rule name="%s"' % name)
    if not enable:
        log('严格拦截: 防火墙规则已移除 (放行恢复)')
        return True
    ok = True
    steps = [
        ('PortalMock-block-tcp', 'protocol=TCP action=block'),
        ('PortalMock-block-udp', 'protocol=UDP action=block'),
        ('PortalMock-allow-80', 'protocol=TCP localport=80 action=allow'),
        ('PortalMock-allow-53', 'protocol=UDP localport=53 action=allow'),
        ('PortalMock-allow-dhcp', 'protocol=UDP localport=67,68 action=allow'),
        ('PortalMock-allow-icmp', 'protocol=ICMPv4 action=allow'),
    ]
    for name, rule in steps:
        code, err = run('netsh advfirewall firewall add rule name="%s" dir=in '
                        'interface="%s" %s' % (name, interface, rule))
        if code != 0:
            ok = False
            log('严格拦截: 规则 %s 添加失败: %s' % (name, err))
            log('严格拦截: 原因通常是未以管理员运行, 或网卡名 [%s] 不存在' % interface)
    # 验证规则是否真实存在
    for name in FW_RULES:
        code, _ = run('netsh advfirewall firewall show rule name="%s"' % name)
        if code == 0:
            log('严格拦截: 规则已生效 [%s]' % name)
    if ok:
        log('严格拦截已启用: 网卡 [%s] 仅放行 80/DNS53, 其余请求全部拦截 (认证前不放行)' % interface)
    return ok


if __name__ == '__main__':
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    svr = PortalServer(port=port, on_log=lambda line: print('[srv]', line))
    svr.start(hijack='--hijack' in sys.argv)
    print('模拟服务器运行中 (Ctrl+C 退出). API: http://127.0.0.1:%d/api' % port)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        svr.stop()
