"""Pure-python BIP340 schnorr + bech32 (no I/O)."""
import hashlib, json, os, sys, time, asyncio
p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
def padd(P1, P2):
    if P1 is None: return P2
    if P2 is None: return P1
    if P1[0] == P2[0] and P1[1] != P2[1]: return None
    if P1 == P2: lam = (3*P1[0]*P1[0]*pow(2*P1[1], p-2, p)) % p
    else: lam = ((P2[1]-P1[1])*pow(P2[0]-P1[0], p-2, p)) % p
    x3 = (lam*lam - P1[0] - P2[0]) % p
    return (x3, (lam*(P1[0]-x3) - P1[1]) % p)
def pmul(P, k):
    R = None
    for i in range(256):
        if (k >> i) & 1: R = padd(R, P)
        P = padd(P, P)
    return R
def th(tag, m):
    t = hashlib.sha256(tag.encode()).digest(); return hashlib.sha256(t+t+m).digest()
b32 = lambda x: x.to_bytes(32, 'big')
i = lambda b: int.from_bytes(b, 'big')
def pubkey(sk): return b32(pmul(G, i(sk))[0])
def sign(sk, msg):
    d0 = i(sk); P = pmul(G, d0); d = d0 if P[1] % 2 == 0 else n-d0
    aux = os.urandom(32)
    t = (d ^ i(th("BIP0340/aux", aux))).to_bytes(32, 'big')
    k0 = i(th("BIP0340/nonce", t + b32(P[0]) + msg)) % n
    R = pmul(G, k0); k = k0 if R[1] % 2 == 0 else n-k0
    e = i(th("BIP0340/challenge", b32(R[0]) + b32(P[0]) + msg)) % n
    return b32(R[0]) + b32((k + e*d) % n)
def verify(pk, msg, sig):
    Px = i(pk); y = pow((pow(Px,3,p)+7)%p, (p+1)//4, p); P=(Px, y if y%2==0 else p-y)
    r, s = i(sig[:32]), i(sig[32:])
    e = i(th("BIP0340/challenge", sig[:32]+pk+msg)) % n
    R = padd(pmul(G, s), pmul(P, n-e))
    return R is not None and R[1] % 2 == 0 and R[0] == r
# bech32
CH = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
def _pm(v):
    g=[0x3b6a57b2,0x26508e6d,0x1ea119fa,0x3d4233dd,0x2a1462b3]; c=1
    for x in v:
        b=c>>25; c=(c&0x1ffffff)<<5^x
        for k in range(5): c ^= g[k] if (b>>k)&1 else 0
    return c
def bech32(hrp, data):
    acc=bits=0; out=[]
    for b in data:
        acc=(acc<<8)|b; bits+=8
        while bits>=5: bits-=5; out.append((acc>>bits)&31)
    if bits: out.append((acc<<(5-bits))&31)
    hx=[ord(x)>>5 for x in hrp]+[0]+[ord(x)&31 for x in hrp]
    pm=_pm(hx+out+[0]*6)^1; chk=[(pm>>5*(5-k))&31 for k in range(6)]
    return hrp+'1'+''.join(CH[d] for d in out+chk)
