"""Key rotation / recovery. The NEW nostr key publishes kind 30078 d='bch-nostr-rotate' with
content 'bch-nostr-rotate.v1:<old_pk>:<new_pk>:<ts>' and tags:
  ['p', old_pk], ['oldsig', <BIP-340 sig by OLD key over sha256(content)>]   (rotation: old key still held)
  ['i', 'bch:<addr from old binding>', <BCH signmessage sig over content>]  (recovery: nostr key lost, BCH key kept)
Valid if the new key signed the event AND at least one of oldsig / BCH sig checks out against
the old binding. Continuity: verifiers follow old -> new and keep attestations tied to the old binding id."""
import sys, os, json, time, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import binding as B, schnorr as nz, bchsig
def make_rotation(new_sk, old_binding, old_sk=None, bch_d=None, ts=None):
    ts = ts or int(time.time()); new = nz.pubkey(new_sk).hex(); old = old_binding['pubkey']
    S = f"bch-nostr-rotate.v1:{old}:{new}:{ts}"; h = hashlib.sha256(S.encode()).digest()
    tags = [['d', 'bch-nostr-rotate'], ['p', old]]
    if old_sk: tags.append(['oldsig', nz.sign(old_sk, h).hex()])
    if bch_d is not None:
        addr = [t for t in old_binding['tags'] if t[0] == 'i'][0][1][4:]
        tags.append(['i', 'bch:' + addr, bchsig.sign_message(bch_d, S.encode())])
    ev = {'pubkey': new, 'created_at': ts, 'kind': 30078, 'content': S, 'tags': tags}
    ev['id'] = B.event_id(ev); ev['sig'] = nz.sign(new_sk, bytes.fromhex(ev['id'])).hex(); return ev
def verify_rotation(ev, old_binding):
    if B.event_id(ev) != ev['id'] or not nz.verify(bytes.fromhex(ev['pubkey']), bytes.fromhex(ev['id']), bytes.fromhex(ev['sig'])): return False, 'bad new-key sig'
    ok, addr, why = B.verify_binding(old_binding)
    if not ok: return False, 'old binding invalid: ' + why
    old = old_binding['pubkey']; p = ev['content'].split(':')
    if len(p) != 4 or p[0] != 'bch-nostr-rotate.v1' or p[1] != old or p[2] != ev['pubkey']: return False, 'statement mismatch'
    h = hashlib.sha256(ev['content'].encode()).digest(); how = []
    for t in ev['tags']:
        if t[0] == 'oldsig' and nz.verify(bytes.fromhex(old), h, bytes.fromhex(t[1])): how.append('old nostr key')
        if t[0] == 'i' and t[1] == 'bch:' + addr and bchsig.verify_address(addr, ev['content'].encode(), t[2]): how.append('bound BCH key')
    return (True, 'ok: ' + old[:12] + ' -> ' + ev['pubkey'][:12] + ' authorized by ' + ' + '.join(how)) if how else (False, 'no valid authorization')
if __name__ == '__main__':
    rnd = lambda: int.from_bytes(os.urandom(32), 'big') % bchsig.n
    o_sk, n_sk, d = os.urandom(32), os.urandom(32), rnd(); ob = B.make_binding(o_sk, d)
    print('rotation:', verify_rotation(make_rotation(n_sk, ob, old_sk=o_sk), ob)[1])
    print('recovery (nostr key lost):', verify_rotation(make_rotation(n_sk, ob, bch_d=d), ob)[1])
    print('attacker w/o old keys:', verify_rotation(make_rotation(n_sk, ob, bch_d=rnd()), ob)[1])
