# -*- coding: utf-8 -*-
"""
AES-128-ECB / ZeroPadding —— 纯 Python 实现, 零第三方依赖。

与 wifi-login 客户端 ui/src/services/aes.js 的 pa_aes_encode / pa_aes_decode 完全一致:
  - key      : "Panabit@1024_key" (16 字节, AES-128)
  - mode     : ECB
  - padding  : ZeroPadding (补 0x00 到 16 字节倍数, 解密后去掉尾部 0x00)
  - 输入/输出: hex 字符串

用于: 模拟 Panabit Portal 服务器时解密客户端上传的 password 密文。
"""

# ---------------------------------------------------------------- 基础运算

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

SBOX = None
INV_SBOX = None


def _gf_mul(a, b):
    """GF(2^8) 乘法 (0x1B 模多项式)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _rotl8(x, n):
    return ((x << n) | (x >> (8 - n))) & 0xFF


def _build_tables():
    """S 盒: GF(2^8) 逆元 + 仿射变换 (与 aes.js 逻辑一致)."""
    global SBOX, INV_SBOX
    if SBOX is not None:
        return
    SBOX = [0] * 256
    INV_SBOX = [0] * 256
    for i in range(256):
        inv = 0
        if i != 0:
            for j in range(1, 256):
                if _gf_mul(i, j) == 1:
                    inv = j
                    break
        s = inv ^ _rotl8(inv, 1) ^ _rotl8(inv, 2) ^ _rotl8(inv, 3) ^ _rotl8(inv, 4) ^ 0x63
        s &= 0xFF
        SBOX[i] = s
        INV_SBOX[s] = i


# ---------------------------------------------------------------- 密钥扩展

def _key_expansion(key_bytes):
    _build_tables()
    w = []
    for i in range(4):
        w.append(list(key_bytes[i * 4:i * 4 + 4]))
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:  # RotWord + SubWord + Rcon
            t = [SBOX[t[1]] ^ RCON[i // 4 - 1], SBOX[t[2]], SBOX[t[3]], SBOX[t[0]]]
        prev = w[i - 4]
        w.append([prev[0] ^ t[0], prev[1] ^ t[1], prev[2] ^ t[2], prev[3] ^ t[3]])
    round_keys = []
    for i in range(11):
        rk = []
        for c in range(4):
            rk.extend(w[i * 4 + c])
        round_keys.append(rk)
    return round_keys


# ---------------------------------------------------------------- 分组变换

def _add_round_key(state, rk):
    for i in range(16):
        state[i] ^= rk[i]


def _sub_bytes(state):
    for i in range(16):
        state[i] = SBOX[state[i]]


def _inv_sub_bytes(state):
    for i in range(16):
        state[i] = INV_SBOX[state[i]]


def _shift_rows(state):
    t = state[1]; state[1] = state[5]; state[5] = state[9]; state[9] = state[13]; state[13] = t
    t = state[2]; state[2] = state[10]; state[10] = t
    t = state[6]; state[6] = state[14]; state[14] = t
    t = state[15]; state[15] = state[11]; state[11] = state[7]; state[7] = state[3]; state[3] = t


def _inv_shift_rows(state):
    t = state[13]; state[13] = state[9]; state[9] = state[5]; state[5] = state[1]; state[1] = t
    t = state[2]; state[2] = state[10]; state[10] = t
    t = state[6]; state[6] = state[14]; state[14] = t
    t = state[3]; state[3] = state[7]; state[7] = state[11]; state[11] = state[15]; state[15] = t


def _mix_columns(state):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3
        state[i + 1] = a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3
        state[i + 2] = a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3)
        state[i + 3] = _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)


def _inv_mix_columns(state):
    for c in range(4):
        i = c * 4
        a0, a1, a2, a3 = state[i], state[i + 1], state[i + 2], state[i + 3]
        state[i] = _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9)
        state[i + 1] = _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13)
        state[i + 2] = _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11)
        state[i + 3] = _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)


def _encrypt_block(inp, rk):
    state = list(inp)
    _add_round_key(state, rk[0])
    for r in range(1, 10):
        _sub_bytes(state); _shift_rows(state); _mix_columns(state); _add_round_key(state, rk[r])
    _sub_bytes(state); _shift_rows(state); _add_round_key(state, rk[10])
    return state


def _decrypt_block(inp, rk):
    state = list(inp)
    _add_round_key(state, rk[10])
    for r in range(9, 0, -1):
        _inv_shift_rows(state); _inv_sub_bytes(state); _add_round_key(state, rk[r]); _inv_mix_columns(state)
    _inv_shift_rows(state); _inv_sub_bytes(state); _add_round_key(state, rk[0])
    return state


# ---------------------------------------------------------------- 编码工具

def _utf8_encode(text):
    out = []
    for ch in str(text if text is not None else ''):
        cp = ord(ch)
        if cp < 0x80:
            out.append(cp)
        elif cp < 0x800:
            out.append(0xC0 | (cp >> 6)); out.append(0x80 | (cp & 0x3F))
        elif 0xD800 <= cp <= 0xDBFF:
            out.append(0xEF); out.append(0xBF); out.append(0xBD)  # 孤立代理 -> U+FFFD
        else:
            out.append(0xE0 | (cp >> 12)); out.append(0x80 | ((cp >> 6) & 0x3F)); out.append(0x80 | (cp & 0x3F))
    return bytes(out)


def _utf8_decode(data):
    out = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b < 0x80:
            out.append(chr(b)); i += 1
        elif (b & 0xE0) == 0xC0 and i + 1 < n:
            out.append(chr(((b & 0x1F) << 6) | (data[i + 1] & 0x3F))); i += 2
        elif (b & 0xF0) == 0xE0 and i + 2 < n:
            out.append(chr(((b & 0x0F) << 12) | ((data[i + 1] & 0x3F) << 6) | (data[i + 2] & 0x3F))); i += 3
        elif (b & 0xF8) == 0xF0 and i + 3 < n:
            cp = ((b & 0x07) << 18) | ((data[i + 1] & 0x3F) << 12) | ((data[i + 2] & 0x3F) << 6) | (data[i + 3] & 0x3F)
            cp -= 0x10000
            out.append(chr(0xD800 + (cp >> 10))); out.append(chr(0xDC00 + (cp & 0x3FF))); i += 4
        else:
            out.append('\ufffd'); i += 1
    return ''.join(out)


# ---------------------------------------------------------------- 对外接口

AES_KEY = _utf8_encode('Panabit@1024_key')
_CACHED_RK = None


def _round_keys():
    global _CACHED_RK
    if _CACHED_RK is None:
        _CACHED_RK = _key_expansion(AES_KEY)
    return _CACHED_RK


def pa_aes_encode(text):
    """明文 -> AES-128-ECB/ZeroPadding -> hex (与客户端 paAesEncode 一致)."""
    rk = _round_keys()
    data = bytearray(_utf8_encode(text))
    rem = len(data) % 16
    if rem != 0:
        data.extend([0] * (16 - rem))
    out = []
    for off in range(0, len(data), 16):
        enc = _encrypt_block(data[off:off + 16], rk)
        out.extend(enc)
    return bytes(out).hex()


def pa_aes_decode(hexstr):
    """hex -> AES-128-ECB 解密 -> 去 ZeroPadding -> utf-8 明文."""
    s = str(hexstr or '').strip()
    if not s or len(s) % 32 != 0 or not all(c in '0123456789abcdefABCDEF' for c in s):
        return ''
    rk = _round_keys()
    data = bytes.fromhex(s)
    plain = bytearray()
    for off in range(0, len(data), 16):
        dec = _decrypt_block(data[off:off + 16], rk)
        plain.extend(dec)
    end = len(plain)
    while end > 0 and plain[end - 1] == 0:
        end -= 1
    return _utf8_decode(bytes(plain[:end]))


if __name__ == '__main__':
    # 自检: 与客户端 aes.js 生成的已知密文比对
    samples = [('123456', '32540191392cdd5d305cac1d0492ba70'),
               ('888888', 'b98d7b6c3ad0fe9e1c1b15439be444a1'),
               ('abc中文', '5e1ed0aeab1e044fda177990e7df76dc')]
    for plain, expect in samples:
        enc = pa_aes_encode(plain)
        dec = pa_aes_decode(expect)
        ok = enc.lower() == expect.lower() and dec == plain
        print(('PASS' if ok else 'FAIL'), repr(plain), 'enc=', enc, 'dec=', repr(dec))
