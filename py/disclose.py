"""Privacy-preserving selective disclosure on top of attest.py (SD-JWT-style salted hashes).
The attester signs an attestation whose claim is only 'sd-sha256:<h1>,<h2>,...' where
h_i = sha256(salt_i || ':' || field_i || '=' || value_i). Nothing personal goes on the relays.
The attester gives the subject (privately) the list of (field, value, salt). Later the subject
reveals ONLY the fields a verifier needs; the verifier checks the attestation (sig + pinned
binding, via attest.verify_attestation) and that each revealed field hashes into the signed list.
Undisclosed fields stay hidden; 16-byte random salts stop guessing low-entropy values."""
import sys, os, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attest, binding as B, bchsig
PFX = 'sd-sha256:'
def _h(f, v, salt): return hashlib.sha256(bytes.fromhex(salt) + f':{f}={v}'.encode()).hexdigest()
def make_sd_attestation(attester_sk, subject_binding, fields: dict):
    """Returns (event, disclosures). Disclosures go to the subject privately, never to relays."""
    disc = [(f, str(v), os.urandom(16).hex()) for f, v in fields.items()]
    hashes = sorted(_h(*d) for d in disc)  # sorted so order leaks nothing
    return attest.make_attestation(attester_sk, subject_binding, PFX + ','.join(hashes)), disc
def verify_disclosure(att, subject_binding, revealed, attester_binding=None):
    """revealed = subset of the (field, value, salt) triples. Returns (ok, reason, {field: value})."""
    ok, why = attest.verify_attestation(att, subject_binding, attester_binding)
    if not ok: return False, why, {}
    claim = {t[0]: t[1] for t in att['tags']}.get('claim', '')
    if not claim.startswith(PFX): return False, 'not a selective-disclosure attestation', {}
    signed = set(claim[len(PFX):].split(','))
    out = {}
    for f, v, s in revealed:
        if _h(f, v, s) not in signed: return False, f'field {f!r} not covered by attestation', {}
        out[f] = v
    return True, f'ok: {len(out)} of {len(signed)} attested field(s) disclosed', out
if __name__ == '__main__':
    rnd = lambda: int.from_bytes(os.urandom(32), 'big') % bchsig.n
    s_sk, a_sk = os.urandom(32), os.urandom(32)
    sb = B.make_binding(s_sk, rnd()); ab = B.make_binding(a_sk, rnd())
    att, disc = make_sd_attestation(a_sk, sb, {'over18': 'true', 'country': 'PT', 'name': 'Alice Example'})
    print('public claim:', att['tags'][-1][1][:60] + '...')
    over18 = [d for d in disc if d[0] == 'over18']
    print('reveal over18 only:', verify_disclosure(att, sb, over18, ab))
    print('forged value:', verify_disclosure(att, sb, [('over18', 'false', over18[0][2])])[:2])
    print('wrong salt:', verify_disclosure(att, sb, [('country', 'PT', '00' * 16)])[:2])
    sb2 = B.make_binding(s_sk, rnd(), ts=sb['created_at'] + 1)
    print('after rebind:', verify_disclosure(att, sb2, over18)[:2])
