# bch-nostr-id

Bind a Nostr pubkey to a Bitcoin Cash address with a statement signed by BOTH keys.

- Event: kind 30078, d=bch-nostr-bind, content `bch-nostr-bind.v1:<nostr-hex>:<cashaddr>:<ts>`,
  tag `["i","bch:<cashaddr>","<base64 BCH signmessage sig>"]`.
- Verify: nostr event id + BIP-340 sig, then recover the BCH signmessage pubkey and compare its cashaddr.
- py/: pure-python reference (bchsig.py, binding.py, auth.py = challenge-response login, discover.py = relay publish/lookup, needs `websockets`).
- index.html: browser verifier + create-binding flow (NIP-07 extension signs the nostr event; you paste a BCH signmessage sig from Electron Cash/Paytaca; no private keys touch the page). noble-curves/noble-hashes ESM. Live at https://bch-nostr-id.surge.sh

Quick test: `cd py && python3 -c "import os,binding;e=binding.make_binding(os.urandom(32),12345);print(binding.verify_binding(e))"`

By Penny. MIT license.

## Pay a Nostr identity (identity-based payments)

The web page can resolve an npub to a BCH address without anyone copy-pasting addresses: it fetches the kind 30078 binding from relays, runs the full verification (event id, BIP-340 sig, statement match, BCH signmessage recovery), and only on success builds a BIP-21 style `bitcoincash:<addr>?amount=<x>` link for the user's wallet. If there is no binding, or it fails verification, it refuses to give an address. A z... (token-aware) address is flagged as able to receive CashTokens.

## Proof-of-payment login ("Prove you are the payer")
A merchant links a session to a BCH payment without accounts. The page builds a fresh challenge `bch-nostr-id payer-proof <txid> <host> <nonce> <time>`. The payer signs it with the key of any input address of that transaction (standard BCH signmessage). The page fetches the transaction's inputs from the public Blockchair API and accepts the signature only if it recovers to one of those input addresses. Nothing is published. Production note: a merchant should check the txid pays its own address and bind the nonce server-side to stop replay.

## Attestations / verifiable credentials (py/attest.py)

Any Nostr key can vouch for a bound identity (e.g. "verified-merchant", "member:org"): kind 30078, d=`bch-nostr-attest:<subject>`, tags `p`=subject, `e`=the exact binding event id, `claim`=text, with content `bch-nostr-attest.v1:<attester>:<subject>:<binding id>:<claim>`. A verifier checks the attester signature, re-verifies the subject's binding, and checks that the attestation pins that binding id. Optionally the attester must itself be BCH-bound. Because the attestation names one binding id, it does not carry over silently when the subject rebinds to a new address. Live example: the web page's "Pay a Nostr identity" box lists verified attestations. Try the npub behind this page: it shows one demo attestation (event aca9e7f5...). Run `python3 py/attest.py` for the self-test: valid, after-rebind (rejected), tampered claim (rejected), unbound attester (rejected).

## Selective disclosure (py/disclose.py)
Privacy-preserving credentials, SD-JWT style. The attester signs a normal attestation (attest.py) whose claim is only `sd-sha256:<h1>,<h2>,...` with h = sha256(salt || ":field=value"), sorted. No personal data goes on the relays. The attester hands the subject the (field, value, salt) triples privately; the subject later reveals only what a verifier needs (e.g. `over18=true`, not name or country). The verifier checks the attester sig + pinned binding, then that each revealed triple hashes into the signed list. Random 16-byte salts stop brute-forcing low-entropy values. Self-test: `python3 py/disclose.py` (reveal 1 of 3 OK; forged value, wrong salt and rebind are all rejected).

## Portable reputation (py/reputation.py)

Reputation here is not a score stored by any service. It is the set of valid attestations about a subject's current binding, which any application can fetch from relays and recompute offline, so it follows the user from app to app. `reputation(subject_binding, attestations, attester_bindings, trusted=None)` keeps only attestations that pass `verify_attestation`, counts only attesters who are themselves BCH-bound (a cheap Sybil brake; the requirement can be turned off), counts each attester once per claim, and lets each verifier pass its own trusted-issuer set, so two apps can weigh the same public data differently. Because attestations pin a binding id, reputation does not carry over silently to a new binding. Self-test: `python3 py/reputation.py` (3 bound attesters counted, unbound attester rejected, duplicate ignored, trust-set filter, rebind -> 0).

## Key rotation and recovery (py/rotate.py)

The NEW Nostr key publishes kind 30078 d=`bch-nostr-rotate` with content `bch-nostr-rotate.v1:<old>:<new>:<ts>`. Authorization is either an `oldsig` tag (a BIP-340 sig by the old Nostr key over sha256(content): normal rotation) or an `i` tag holding a BCH signmessage sig from the address in the old binding (recovery when the Nostr key is lost or compromised). Verifiers follow old -> new, so identity continuity and the attestations tied to the old binding id are kept. Self-test: rotation ok, recovery ok, attacker without old keys rejected. Limitation: if both old keys leak, the attacker can rotate too. A future version could add a time-locked BCH commitment or a pre-committed next-key hash.

Web check: the page's "Pay a Nostr identity" flow also queries rotate events (`#p`=old key, d=bch-nostr-rotate), verifies them the same way as verify_rotation(), and warns "KEY ROTATED" before showing a payment link. If several valid rotate events exist, it reports the latest one (by created_at) and how many there are. Live demo: throwaway key 0262ecef.. was rotated to 42f919bc.. (authorized by the old nostr key) and later recovered to 30855b60.. (authorized by the bound BCH key); the page shows the latest of the 2.

## NIP-39 profile claim (optional)
Copy the binding's `["i","bch:<cashaddr>","<sig>"]` tag into your kind 0 profile tags so NIP-39-aware clients can display it. The kind 30078 event remains the full record: the proof signs the statement `bch-nostr-bind.v1:<pubkey>:<cashaddr>:<ts>`, so a verifier needs the binding event (or the ts) to check it.

## Interoperability with Electron Cash (tested 2026-11-02)

Signatures use the standard Bitcoin Signed Message format, so they work with Electron Cash
in both directions. Checked against the Electron Cash 4.4.6 release, which was verified
against its SHA256 and its PGP signature (Jonald Fyookball, 4FD06489EFF1DDE1):

- A binding signature produced here is accepted by `electron-cash verifymessage <addr> <sig> <msg>`,
  and the same signature with a tampered message is rejected.
- A message signed in Electron Cash (`signmessage`) verifies with this page's verifier;
  if the message is changed, verification fails.

That means you can create the BCH half of a binding in Electron Cash (Tools > Sign/verify message)
and paste the signature in here.
