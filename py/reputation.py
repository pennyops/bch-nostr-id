"""Portable reputation over BCH<->Nostr bindings.
Reputation = the set of valid attestations (attest.py) about a subject's CURRENT binding,
gathered from any relays. Any app can recompute it offline from the same public events,
so it follows the user across applications with no central score keeper.
Sybil damping: by default only attesters that are themselves BCH-bound count, each
attester counts once per claim, and a verifier may pass its own trusted attester set."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest as A

def reputation(subject_binding, attestations, attester_bindings=None, trusted=None, require_bound=True):
    """attester_bindings: {attester_pubkey: binding_event}. trusted: optional set of pubkeys.
    Returns {'claims': {claim: [attester_pk,...]}, 'attesters': n, 'rejected': [(id, reason)]}."""
    attester_bindings = attester_bindings or {}
    claims, rejected, seen = {}, [], set()
    for att in attestations:
        pk = att.get('pubkey', '')
        if trusted is not None and pk not in trusted:
            rejected.append((att.get('id', '')[:12], 'attester not in verifier trust set')); continue
        ab = attester_bindings.get(pk)
        if require_bound and ab is None:
            rejected.append((att.get('id', '')[:12], 'attester has no BCH binding')); continue
        ok, why = A.verify_attestation(att, subject_binding, ab)
        if not ok:
            rejected.append((att.get('id', '')[:12], why)); continue
        claim = {t[0]: t[1] for t in att['tags']}.get('claim', '')
        if (pk, claim) in seen: continue
        seen.add((pk, claim)); claims.setdefault(claim, []).append(pk)
    return {'claims': {c: sorted(v) for c, v in claims.items()},
            'attesters': len({p for p, _ in seen}), 'rejected': rejected}

if __name__ == '__main__':
    import binding as B, bchsig
    rnd = lambda: int.from_bytes(os.urandom(32), 'big') % bchsig.n
    s_sk = os.urandom(32); sb = B.make_binding(s_sk, rnd())
    keys = [os.urandom(32) for _ in range(3)]
    binds = {}
    for k in keys:
        b = B.make_binding(k, rnd()); binds[b['pubkey']] = b
    atts = [A.make_attestation(keys[0], sb, 'verified-merchant'),
            A.make_attestation(keys[1], sb, 'verified-merchant'),
            A.make_attestation(keys[1], sb, 'verified-merchant'),  # duplicate, counted once
            A.make_attestation(keys[2], sb, 'paid-on-time')]
    sybil = os.urandom(32); atts.append(A.make_attestation(sybil, sb, 'verified-merchant'))  # unbound
    r = reputation(sb, atts, binds)
    print('claims:', {c: len(v) for c, v in r['claims'].items()}, 'attesters:', r['attesters'])
    print('rejected:', [w for _, w in r['rejected']])
    only = reputation(sb, atts, binds, trusted={atts[0]['pubkey']})
    print('verifier trusting 1 issuer:', {c: len(v) for c, v in only['claims'].items()})
    sb2 = B.make_binding(s_sk, rnd(), ts=sb['created_at'] + 1)
    print('after subject rebinds:', reputation(sb2, atts, binds)['attesters'], 'attesters (old creds not inherited)')
