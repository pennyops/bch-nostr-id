"""BCH<->Nostr identity binding prototype (v1). Statement signed by BOTH keys:
 - BCH key: Bitcoin signed message over the statement (proves control of the cashaddr)
 - Nostr key: the event carrying it is a BIP-340 signed nostr event (proves control of the npub)
Event: kind 30078 (addressable app data), d-tag 'bch-nostr-bind', tags i=['i','bch:<addr>',<sig>] (NIP-39 style)."""
import sys, json, time, hashlib, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bchsig
import schnorr as nz  # pure-python schnorr: pubkey/sign/verify
def statement(npub_hex, addr, ts): return f"bch-nostr-bind.v1:{npub_hex}:{addr}:{ts}"
def event_id(ev):
    ser = json.dumps([0, ev['pubkey'], ev['created_at'], ev['kind'], ev['tags'], ev['content']], separators=(',', ':'), ensure_ascii=False)
    return hashlib.sha256(ser.encode()).hexdigest()
def make_binding(nostr_sk: bytes, bch_d: int, ts=None):
    ts = ts or int(time.time()); pk = nz.pubkey(nostr_sk).hex()
    addr = bchsig.cashaddr_p2pkh(bchsig.ser_pub(bchsig.pmul(bchsig.G, bch_d)))
    S = statement(pk, addr, ts); bsig = bchsig.sign_message(bch_d, S.encode())
    ev = {'pubkey': pk, 'created_at': ts, 'kind': 30078, 'content': S,
          'tags': [['d', 'bch-nostr-bind'], ['i', 'bch:' + addr, bsig], ['statement', S]]}
    ev['id'] = event_id(ev); ev['sig'] = nz.sign(nostr_sk, bytes.fromhex(ev['id'])).hex()
    return ev
def verify_binding(ev):
    """Returns (ok, addr, reason). Offline; no central authority."""
    if event_id(ev) != ev['id']: return False, None, 'bad id'
    if not nz.verify(bytes.fromhex(ev['pubkey']), bytes.fromhex(ev['id']), bytes.fromhex(ev['sig'])): return False, None, 'bad nostr sig'
    i = [t for t in ev['tags'] if t[0] == 'i' and t[1].startswith('bch:')]
    if len(i) != 1: return False, None, 'no bch i-tag'
    addr, bsig = i[0][1][4:], i[0][2]; S = ev['content']
    parts = S.split(':')
    if len(parts) != 5 or parts[0] != 'bch-nostr-bind.v1' or parts[1] != ev['pubkey'] or ':'.join(parts[2:4]) != addr: return False, addr, 'statement mismatch'
    if not bchsig.verify_address(addr, S.encode(), bsig): return False, addr, 'bad bch sig'
    return True, addr, 'ok'
if __name__ == '__main__':
    sk = os.urandom(32); d = int.from_bytes(os.urandom(32), 'big') % bchsig.n
    ev = make_binding(sk, d); print(json.dumps(ev)[:200]); print(verify_binding(ev))
    ev2 = dict(ev); ev2['tags'] = [t if t[0] != 'i' else ['i', 'bch:bitcoincash:qp63uahgrxged4z5jswyt5dn5v3lzsem6cy4spdc2h', t[2]] for t in ev['tags']]
    print('tampered:', verify_binding(ev2)[2])
