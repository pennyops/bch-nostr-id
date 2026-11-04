# BCH <-> Nostr identity binding (prototype v1)

Goal: let anyone prove "this Nostr key and this Bitcoin Cash address belong to the same person", let apps find that proof without a central database, and let users log in to apps with it.

## Pieces

- bchsig.py: secp256k1 ECDSA, BCH CashAddr encode/decode, standard Bitcoin signed-message format (sign / recover / verify against a cashaddr). Cross-checked against python-bitcoinlib (xcheck_bitcoinlib.py), so signatures interoperate with wallets that support standard message signing (e.g. Electron Cash).
- binding.py: makes and verifies the binding event.
- discover.py: publishes the binding to public relays and looks it up by npub.
- auth.py: challenge-response login against a verified binding.

## 1. Binding statement

    bch-nostr-bind.v1:<nostr_pubkey_hex>:<cashaddr>:<unix_ts>

Both keys sign this statement:
- BCH key: a Bitcoin signed message over the statement (base64, 65-byte recoverable sig). This proves the holder controls the cashaddr.
- Nostr key: the statement is the content of a BIP-340 signed Nostr event, which proves the holder controls the npub.

The two private keys stay separate, and neither is ever revealed. Putting the npub inside the BCH-signed text, and the cashaddr inside the Nostr-signed event, means neither signature can be lifted and reused for a different identity.

## 2. Event format (discovery)

    kind: 30078 (addressable app data, NIP-78), so it is replaceable per author
    tags: ["d","bch-nostr-bind"]
          ["i","bch:<cashaddr>","<bch_signature_b64>"]   (NIP-39 external-identity style)
          ["statement","<statement>"]
    content: <statement>

Discovery: REQ {kinds:[30078], authors:[pk], "#d":["bch-nostr-bind"]} on any relays. A verifier keeps only events that pass both signature checks and takes the newest one. Relays are untrusted transport: a relay can withhold an event but cannot forge one.

## 3. Verification (offline, no authority)

1. Recompute the NIP-01 event id and check the BIP-340 signature against the event pubkey.
2. Parse the statement and check that it names this pubkey and the cashaddr in the i-tag.
3. Recover the pubkey from the BCH message signature, hash160 it, and compare against the cashaddr payload.

## 4. Login (challenge-response)

The app issues a random nonce. The user returns:
- a kind 22242 event (NIP-42 style) with tags challenge=<nonce> and app=<app id>, signed by the Nostr key
- optionally, a BCH signed message `bch-nostr-auth.v1:<app>:<nonce>`, which proves live control of both keys

The app checks the binding, the matching pubkey, the signatures, the nonce, the app id, and freshness (300 s). Because the app id is part of what gets signed, a response captured by one app cannot be replayed to another.

## Status / next

Done and tested: binding, live relay publish and discovery (5 relays), verification, auth.
Next: browser demo (JS verifier and login page), identity-based payments (resolve npub -> cashaddr -> pay), key rotation (the new binding is co-signed by the old BCH key, or there is an explicit revocation event), and a NIP-05-style lookup.
