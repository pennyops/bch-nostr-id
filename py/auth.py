"""Challenge-response auth against a verified binding (offline, no central authority).
App: nonce = new_challenge(). User: resp = answer(nostr_sk, bch_d, nonce, app). App: check(binding_ev, resp, nonce, app)."""
import os, json, time, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import binding as B, bchsig
def new_challenge(): return os.urandom(16).hex()
def answer(nostr_sk, bch_d, nonce, app, ts=None):
    ts = ts or int(time.time()); pk = B.nz.pubkey(nostr_sk).hex()
    ev = {'pubkey': pk, 'created_at': ts, 'kind': 22242, 'content': '',  # NIP-42 style auth event
          'tags': [['challenge', nonce], ['app', app]]}
    ev['id'] = B.event_id(ev); ev['sig'] = B.nz.sign(nostr_sk, bytes.fromhex(ev['id'])).hex()
    bsig = bchsig.sign_message(bch_d, f"bch-nostr-auth.v1:{app}:{nonce}".encode()) if bch_d else None
    return {'event': ev, 'bch_sig': bsig}
def check(binding_ev, resp, nonce, app, max_age=300):
    ok, addr, why = B.verify_binding(binding_ev)
    if not ok: return False, 'binding: ' + why
    ev = resp['event']
    if ev['pubkey'] != binding_ev['pubkey']: return False, 'pubkey mismatch'
    if B.event_id(ev) != ev['id'] or not B.nz.verify(bytes.fromhex(ev['pubkey']), bytes.fromhex(ev['id']), bytes.fromhex(ev['sig'])): return False, 'bad auth sig'
    tags = {t[0]: t[1] for t in ev['tags']}
    if tags.get('challenge') != nonce or tags.get('app') != app: return False, 'wrong challenge/app'
    if abs(time.time() - ev['created_at']) > max_age: return False, 'stale'
    if resp.get('bch_sig') and not bchsig.verify_address(addr, f"bch-nostr-auth.v1:{app}:{nonce}".encode(), resp['bch_sig']): return False, 'bad bch auth sig'
    return True, f"authenticated npub {ev['pubkey'][:12]}.. + {addr}" + (' (both keys)' if resp.get('bch_sig') else ' (nostr key)')
if __name__ == '__main__':
    sk = os.urandom(32); d = int.from_bytes(os.urandom(32), 'big') % bchsig.n
    bev = B.make_binding(sk, d); c = new_challenge()
    print(check(bev, answer(sk, d, c, 'demo.app'), c, 'demo.app'))
    print(check(bev, answer(sk, d, c, 'demo.app'), new_challenge(), 'demo.app'))
    print(check(bev, answer(os.urandom(32), None, c, 'demo.app'), c, 'demo.app'))
