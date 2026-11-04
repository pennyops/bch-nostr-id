"""Third-party attestations (verifiable credentials) over a BCH<->Nostr binding.
An attester (any Nostr key; ideally itself bound to a BCH address) publishes kind 30078,
d-tag 'bch-nostr-attest:<subject_pk>', tags p=subject, e=<binding event id>, claim=<text>.
The attestation pins the exact binding it vouches for, so a rebinding by the subject
does not silently inherit old credentials. Verification is offline: attester sig +
subject binding validity + id match (+ optional: attester's own binding)."""
import sys, os, json, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import binding as B, schnorr as nz, bchsig
def make_attestation(attester_sk: bytes, subject_binding: dict, claim: str, ts=None):
    ts = ts or int(time.time()); pk = nz.pubkey(attester_sk).hex(); sub = subject_binding['pubkey']
    S = f"bch-nostr-attest.v1:{pk}:{sub}:{subject_binding['id']}:{claim}"
    ev = {'pubkey': pk, 'created_at': ts, 'kind': 30078, 'content': S,
          'tags': [['d', 'bch-nostr-attest:' + sub], ['p', sub], ['e', subject_binding['id']], ['claim', claim]]}
    ev['id'] = B.event_id(ev); ev['sig'] = nz.sign(attester_sk, bytes.fromhex(ev['id'])).hex(); return ev
def verify_attestation(att, subject_binding, attester_binding=None):
    """Returns (ok, reason). attester_binding optional: if given, attester must be BCH-bound too."""
    if B.event_id(att) != att['id']: return False, 'bad id'
    if not nz.verify(bytes.fromhex(att['pubkey']), bytes.fromhex(att['id']), bytes.fromhex(att['sig'])): return False, 'bad attester sig'
    ok, addr, why = B.verify_binding(subject_binding)
    if not ok: return False, 'subject binding invalid: ' + why
    tg = {t[0]: t[1] for t in att['tags']}
    if tg.get('p') != subject_binding['pubkey'] or tg.get('e') != subject_binding['id']: return False, 'not about this binding'
    if att['content'] != f"bch-nostr-attest.v1:{att['pubkey']}:{tg['p']}:{tg['e']}:{tg.get('claim','')}": return False, 'statement mismatch'
    if attester_binding is not None:
        ok2, a2, w2 = B.verify_binding(attester_binding)
        if not ok2 or attester_binding['pubkey'] != att['pubkey']: return False, 'attester not bound'
    return True, 'ok: ' + att['pubkey'][:12] + ' attests "' + tg.get('claim','') + '" for ' + addr
if __name__ == '__main__':
    rnd = lambda: int.from_bytes(os.urandom(32), 'big') % bchsig.n
    s_sk, a_sk = os.urandom(32), os.urandom(32)
    sb = B.make_binding(s_sk, rnd()); ab = B.make_binding(a_sk, rnd())
    att = make_attestation(a_sk, sb, 'verified-merchant')
    print(verify_attestation(att, sb, ab))
    sb2 = B.make_binding(s_sk, rnd(), ts=sb['created_at'] + 1)  # subject rebinds
    print('after rebind:', verify_attestation(att, sb2)[1])
    bad = dict(att); bad['tags'] = [t if t[0] != 'claim' else ['claim', 'bank'] for t in att['tags']]
    print('tampered claim:', verify_attestation(bad, sb)[1])
    print('unbound attester:', verify_attestation(att, sb, sb)[1])
