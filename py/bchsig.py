"""Pure-python BCH signed-message (Electron Cash / Bitcoin 'signmessage') sign + recover, and cashaddr P2PKH.
Prototype for the BCH<->Nostr identity binding. No deps. Secrets never hardcoded."""
import hashlib, hmac, base64
p = 2**256 - 2**32 - 977
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def padd(A, B):
    if A is None: return B
    if B is None: return A
    if A[0] == B[0] and A[1] != B[1]: return None
    if A == B: l = 3*A[0]*A[0]*pow(2*A[1], p-2, p) % p
    else: l = (B[1]-A[1])*pow(B[0]-A[0], p-2, p) % p
    x = (l*l - A[0] - B[0]) % p
    return (x, (l*(A[0]-x) - A[1]) % p)
def pmul(P, k):
    R = None
    while k:
        if k & 1: R = padd(R, P)
        P = padd(P, P); k >>= 1
    return R
def sha(b): return hashlib.sha256(b).digest()
def varint(x): return bytes([x]) if x < 253 else b'\xfd' + x.to_bytes(2, 'little')
def msg_hash(msg: bytes):
    m = b"\x18Bitcoin Signed Message:\n" + varint(len(msg)) + msg
    return sha(sha(m))
def ser_pub(P): return bytes([2 + (P[1] & 1)]) + P[0].to_bytes(32, 'big')
def nonce_rfc6979(d, h):
    x = d.to_bytes(32, 'big'); V = b'\x01'*32; K = b'\x00'*32
    K = hmac.new(K, V+b'\x00'+x+h, 'sha256').digest(); V = hmac.new(K, V, 'sha256').digest()
    K = hmac.new(K, V+b'\x01'+x+h, 'sha256').digest(); V = hmac.new(K, V, 'sha256').digest()
    while True:
        V = hmac.new(K, V, 'sha256').digest(); k = int.from_bytes(V, 'big')
        if 1 <= k < n: return k
        K = hmac.new(K, V+b'\x00', 'sha256').digest(); V = hmac.new(K, V, 'sha256').digest()
def sign_message(d: int, msg: bytes) -> str:
    h = msg_hash(msg); z = int.from_bytes(h, 'big'); k = nonce_rfc6979(d, h)
    R = pmul(G, k); r = R[0] % n; s = pow(k, n-2, n)*(z + r*d) % n
    rec = R[1] & 1
    if s > n//2: s = n - s; rec ^= 1
    return base64.b64encode(bytes([27 + rec + 4]) + r.to_bytes(32, 'big') + s.to_bytes(32, 'big')).decode()
def recover(msg: bytes, sig_b64: str):
    sig = base64.b64decode(sig_b64); hdr = sig[0] - 27; rec = hdr & 3
    r = int.from_bytes(sig[1:33], 'big'); s = int.from_bytes(sig[33:65], 'big')
    x = r + (rec >> 1)*n; y = pow((x*x*x + 7) % p, (p+1)//4, p)
    if (y & 1) != (rec & 1): y = p - y
    R = (x, y); z = int.from_bytes(msg_hash(msg), 'big'); ri = pow(r, n-2, n)
    Q = padd(pmul(R, s*ri % n), pmul(G, (n - z)*ri % n))
    return Q, bool(hdr & 4)
# cashaddr
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _polymod(v):
    c = 1
    for d in v:
        c0 = c >> 35; c = ((c & 0x07ffffffff) << 5) ^ d
        for i, g in enumerate([0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470]):
            if (c0 >> i) & 1: c ^= g
    return c ^ 1
def _conv(data, f, t):
    acc = bits = 0; out = []
    for b in data:
        acc = (acc << f) | b; bits += f
        while bits >= t: bits -= t; out.append((acc >> bits) & ((1 << t)-1))
    if bits: out.append((acc << (t-bits)) & ((1 << t)-1))
    return out
def cashaddr_p2pkh(pub33: bytes, prefix="bitcoincash", ver=0):  # ver 0x10 = token-aware (z...)
    h160 = hashlib.new('ripemd160', sha(pub33)).digest()
    payload = _conv(bytes([ver]) + h160, 8, 5)
    pm = _polymod([ord(c) & 31 for c in prefix] + [0] + payload + [0]*8)
    return prefix + ":" + "".join(CH[x] for x in payload + [(pm >> 5*(7-i)) & 31 for i in range(8)])
def verify_address(addr: str, msg: bytes, sig_b64: str):
    Q, comp = recover(msg, sig_b64)
    if not comp: return False
    return addr in (cashaddr_p2pkh(ser_pub(Q), addr.split(':')[0]), cashaddr_p2pkh(ser_pub(Q), addr.split(':')[0], 0x10))
if __name__ == "__main__":
    import os
    d = int.from_bytes(os.urandom(32), 'big') % n
    addr = cashaddr_p2pkh(ser_pub(pmul(G, d)))
    m = b"bch-nostr-bind.v1:test"
    s = sign_message(d, m)
    print(addr, verify_address(addr, m, s), verify_address(addr, m + b"x", s))
    # known vector: privkey 1 -> legacy 1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH = cashaddr below
    print(cashaddr_p2pkh(ser_pub(G)) == "bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h")
