#!/usr/bin/env node
/**
 * 模拟 Panabit Portal 认证服务器 (本地验证 wifi-login 客户端用)
 * ============================================================
 * 用途: 在有道词典笔 / 浏览器 / 脚本中验证 wifi-login 的登录、状态心跳、设备管理流程,
 *       不需要真实 Panabit 网关。
 *
 * 实现契约 (与 wifi-login ui/src/services/portal-adapters/panabit.js 对应):
 *   GET /api?route=portal&action=load_portal_conf   -> {code:0, data:{policy:{auth1,scene_str}}}
 *   GET /api?route=webauth&action=user_login        -> {code:0, data:{stat:1}} / {code:255, msg:'INV_NAMEORPWD'}
 *   GET /api?route=webauth&action=query_auth_stat   -> {code:0, data:{stat:0|1}}
 *   GET /api?route=ucenter&action=load_user_list    -> {code:0, data:[{name,ipstr,clntmac,birth,uid}]}
 *   GET /api?route=ucenter&action=user_offone       -> {code:0}
 *   GET /api?route=ucenter&action=user_offall       -> {code:0}
 *   GET /portal/?userip=..&userurl=..               -> 模拟跳转登录页 (浏览器直接看效果)
 *
 * 密码加密: AES-128-ECB / ZeroPadding, 密钥 "Panabit@1024_key"
 *   (与客户端 aes.js 的 paAesEncode 完全一致, 服务器解密后校验)
 *
 * 注意: 真实 Panabit 响应中文为 GB2312, 客户端 sanitize 只保留 ASCII,
 *       所以本服务器故意只用 ASCII 消息, 两种环境行为一致。
 *
 * 启动:  node mock-panabit-portal.js            (默认 8080 端口)
 *        PORT=9090 node mock-panabit-portal.js  (改端口)
 */
'use strict'

const http = require('http')
const crypto = require('crypto')

const PORT = Number(process.env.PORT || 8080)
const AES_KEY = Buffer.from('Panabit@1024_key', 'latin1')

/* ---------------- 测试账号 (改成你自己的) ---------------- */
const ACCOUNTS = {
  admin: '123456',
  test: '888888',
}

/* ---------------- 模拟在线设备表 ---------------- */
let onlineDevices = [
  { name: '词典笔-本机', ipstr: '10.10.10.100', clntmac: 'AA:BB:CC:DD:EE:01', birth: '12:00:01', uid: '1' },
  { name: '我的手机', ipstr: '10.10.10.55', clntmac: 'AA:BB:CC:DD:EE:02', birth: '11:30:00', uid: '2' },
]

/* 会话状态: ip -> { authed: bool } (query_auth_stat 用) */
const sessions = new Map()

/* ---------------- AES-128-ECB / ZeroPadding 解密 ---------------- */
function paAesDecode(hex) {
  if (!/^[0-9a-fA-F]+$/.test(String(hex || '')) || String(hex).length % 32 !== 0) return ''
  try {
    const buf = Buffer.from(hex, 'hex')
    const decipher = crypto.createDecipheriv('aes-128-ecb', AES_KEY, null)
    decipher.setAutoPadding(false)
    const out = Buffer.concat([decipher.update(buf), decipher.final()])
    /* ZeroPadding: 去掉尾部 0x00 */
    let end = out.length
    while (end > 0 && out[end - 1] === 0) end--
    return out.slice(0, end).toString('utf8')
  } catch (e) {
    return ''
  }
}

/* ---------------- JSON 响应 ---------------- */
function sendJson(res, obj) {
  const body = JSON.stringify(obj)
  res.writeHead(200, { 'Content-Type': 'text/plain; charset=ascii' })
  res.end(body)
}

function ok(data) {
  return { code: 0, msg: 'success', data: data === undefined ? null : data }
}

/* ---------------- 请求处理 ---------------- */
const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost')
  const q = url.searchParams
  const route = q.get('route') || ''
  const action = q.get('action') || ''

  /* 模拟 302 跳转登录页 (浏览器访问 http://<PC-IP>:8080/portal/ 看效果) */
  if (url.pathname === '/portal/' || url.pathname === '/portal') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
    res.end(
      '<html><head><title>Panabit 上网认证</title></head>' +
      '<body><h2>模拟 Panabit Portal 登录页</h2>' +
      '<p>跳转参数: userip=' + (q.get('userip') || '') + ' userurl=' + (q.get('userurl') || '') + '</p>' +
      '<p>客户端应通过 /api 接口完成认证, 本页仅供浏览器查看。</p></body></html>'
    )
    return
  }

  if (url.pathname !== '/api') {
    res.writeHead(404)
    res.end('not found')
    return
  }

  const ip = q.get('ip') || q.get('userip') || q.get('wlanuserip') || ''

  /* ---- route=portal ---- */
  if (route === 'portal' && action === 'load_portal_conf') {
    /* 模拟 MAC 免认证: ip 以 .200 结尾直接放行 (可自行改规则) */
    if (ip.endsWith('.200')) {
      sendJson(res, { code: 200, msg: 'MAC auth passed', data: null })
      return
    }
    sendJson(res, ok({ policy: { auth1: 'panabit', scene_str: 'test-scene' } }))
    return
  }

  /* ---- route=webauth ---- */
  if (route === 'webauth' && action === 'user_login') {
    const username = q.get('username') || ''
    const pwdHex = q.get('password') || ''
    const plain = paAesDecode(pwdHex)
    console.log('[login] user=' + username + ' pwd(decrypted)=' + plain + ' ip=' + ip)
    if (!ACCOUNTS[username] || ACCOUNTS[username] !== plain) {
      sendJson(res, { code: 255, msg: 'INV_NAMEORPWD', data: null })
      return
    }
    /* 登录成功: 记会话, 并把设备加入在线列表 */
    sessions.set(ip || '0.0.0.0', { authed: true })
    if (ip && !onlineDevices.some((d) => d.ipstr === ip)) {
      onlineDevices.push({ name: username, ipstr: ip, clntmac: 'AA:BB:CC:DD:EE:03', birth: '12:30:00', uid: String(Date.now()) })
    }
    sendJson(res, ok({ stat: 1 }))
    return
  }

  if (route === 'webauth' && action === 'query_auth_stat') {
    const s = sessions.get(ip || '0.0.0.0')
    sendJson(res, ok({ stat: s && s.authed ? 1 : 0 }))
    return
  }

  /* ---- route=ucenter ---- */
  if (route === 'ucenter' && action === 'load_user_list') {
    sendJson(res, ok(onlineDevices))
    return
  }
  if (route === 'ucenter' && action === 'user_offone') {
    const addr = q.get('addr') || ''
    onlineDevices = onlineDevices.filter((d) => d.ipstr !== addr)
    console.log('[offone] addr=' + addr + ' remaining=' + onlineDevices.length)
    sendJson(res, ok(null))
    return
  }
  if (route === 'ucenter' && action === 'user_offall') {
    onlineDevices = []
    sessions.clear()
    console.log('[offall] all devices offline')
    sendJson(res, ok(null))
    return
  }

  sendJson(res, { code: -1, msg: 'unknown route/action: ' + route + '/' + action, data: null })
})

server.listen(PORT, '0.0.0.0', () => {
  console.log('模拟 Panabit Portal 服务器已启动:')
  console.log('  本机:      http://127.0.0.1:' + PORT)
  console.log('  局域网:    http://<本机局域网IP>:' + PORT + '  (客户端/词典笔用这个)')
  console.log('  登录页:    http://127.0.0.1:' + PORT + '/portal/?userip=10.10.10.100&userurl=http://example.com')
  console.log('  测试账号:  ' + Object.keys(ACCOUNTS).map((u) => u + '/' + ACCOUNTS[u]).join(', '))
})
