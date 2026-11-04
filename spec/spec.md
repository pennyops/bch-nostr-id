# Draft: finding a BCH payment address from a Nostr npub

Status: draft for discussion. Written for [Cashonize issue #405](https://github.com/cashonize/cashonize-wallet/issues/405) ("pay to a Nostr identity once a BCH standard exists"). License: CC0. Reference implementation, live now: [bch-nostr-id.surge.sh](https://bch-nostr-id.surge.sh) (JS lookup/verify page plus MIT Python tools).

## Goal

A sender types or picks an `npub` in a wallet's send form or address book. The wallet finds a BCH address that the **owner of that npub agreed to**, shows it, and lets the sender confirm. No new server, no custodian, and nothing for relays to forge.

Issue #405 lists three directions. This draft takes direction 1 (an address published in a Nostr event) and adds direction 3 (a reusable paycode) as an optional field. It rejects direction 2 (paying to the npub key itself) for the reason given under Privacy and safety.

## 1. The binding event

One addressable Nostr event, published by the npub:

```
kind:       30078
tags:       ["d", "bch-nostr-bind"]
            ["i", "bch:<cashaddr>", "<base64 BCH signmessage signature>"]
            ["statement", "<statement>"]
content:    <statement>
statement:  bch-nostr-bind.v1:<nostr pubkey hex>:<cashaddr>:<unix ts>
```

- `<cashaddr>` is a full `bitcoincash:` address. A token-aware `z...` address is allowed and lets the sender's wallet send CashTokens.
- The BCH signature is a standard Bitcoin Cash `signmessage` signature (the format Electron Cash produces) by the key of `<cashaddr>`, over the exact statement string.
- Because the event is addressable (kind 30000-39999 with a `d` tag), publishing a new one replaces the old one on relays.

So there are **two signatures**: the Nostr key signs the event (the npub claims the address), and the BCH key signs the statement (the address owner claims the npub). A relay or a third party can't fake either.

## 2. Optional kind 0 claim

The same `["i","bch:<cashaddr>",...]` tag may also be copied into the profile (kind 0) tags, NIP-39 style, so clients that render external identities show it. A wallet must not treat a kind 0 claim alone as verified: it can show it with a warning ("unverified, address not signed"), or ignore it.

## 3. Resolution (wallet side)

1. Decode the npub to its hex pubkey.
2. Query relays for `{"kinds":[30078], "authors":[<pk>], "#d":["bch-nostr-bind"]}`. Relays: the user's NIP-65 list if known, plus a user-changeable default list (in line with the wallet's network privacy settings).
3. Take the newest event that passes:
   - event id and BIP-340 signature valid for `<pk>`;
   - `content` parses as `bch-nostr-bind.v1`, and its pubkey equals `<pk>`;
   - the `i` tag's address equals the statement address;
   - the BCH signmessage signature verifies against that address.
4. Check for a key rotation (section 4). If a valid one exists, warn and point the user at the new key.
5. Show the address (and a `bitcoincash:` URI) for confirmation. **Never auto-send** on resolution.
6. Nothing valid found: no payment. Optionally fall back to a kind 0 claim, with a clear warning.

Address books should store the npub, not the resolved address, and re-resolve at send time (the owner may have moved). Caching the last verified address to flag changes is a good idea.

## 4. Key rotation and recovery

If a Nostr key is lost or replaced, the **new** key publishes:

```
kind:     30078
tags:     ["d", "bch-nostr-rotate"], ["p", <old pk>]
          ["oldsig", <BIP-340 sig by the old key over sha256(content)>]   and/or
          ["i", "bch:<bound cashaddr>", <BCH signmessage sig over content>]
content:  bch-nostr-rotate.v1:<old pk hex>:<new pk hex>:<unix ts>
```

A rotation is valid if it's authorized by the old Nostr key **or** by the BCH key bound to the old identity. The second path covers a lost nsec: the bound BCH wallet can still vouch for the new key. Wallets that find a valid rotation should warn ("this identity moved to npub...") rather than silently switching.

## 5. Privacy and safety

- **One public address.** Direction 1 ties a single address to a public identity, so anyone can see the payments it receives. That's fine for tips and donations, but not for everything.
- **Optional paycode (direction 3).** A binding may add `["rpa", "<paycode>"]` (the Reusable Addresses paycode format). Wallets that support RPA derive a fresh address per payment, and other wallets fall back to the cashaddr. The paycode should be covered by the BCH signature in a v2 statement. That's left open here on purpose until a wallet implements RPA sending.
- **Why not direction 2 (pay the npub key).** The nsec usually sits in several Nostr clients and browser extensions, so it's a weak guard for money. It would also need new wallet code to spend from a Nostr key. A separate BCH key that signs a binding keeps the two roles apart.
- **Relay privacy.** Lookups reveal to the relay which npub the sender is about to pay. A user-changeable relay list (or the wallet's own relay) limits this.

## 6. Open questions for wallet devs

1. Is kind 30078 with `d=bch-nostr-bind` acceptable, or would a dedicated NIP kind be preferred? (30078 works on every relay today.)
2. Should the statement add a chain/network field (mainnet vs chipnet), or is the cashaddr prefix enough? (`bchtest:` addresses already carry it.)
3. Should the kind 0 fallback exist at all?

## 7. Reference implementation

- Lookup + verify in the browser, with no backend: [bch-nostr-id.surge.sh](https://bch-nostr-id.surge.sh) (the "Pay" section runs exactly steps 1-5 above).
- Python: create/verify a binding, rotation, and a payment watcher (MIT), linked from the same page.
- BCH signatures tested both ways against Electron Cash 4.4.6 (q and z addresses).
