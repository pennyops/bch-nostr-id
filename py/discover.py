"""Publish + discover BCH<->Nostr bindings via public relays (no central DB).
usage: discover.py demo            -> make throwaway keys, publish binding, re-fetch from relays, verify
       discover.py lookup <pk_hex> -> fetch kind 30078 d=bch-nostr-bind for that npub from relays, verify, print BCH addr
"""
import sys, os, json, asyncio, websockets
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bchsig, binding
import schnorr as nz

RELAYS = ["wss://nos.lol", "wss://relay.primal.net", "wss://nostr.mom", "wss://offchain.pub", "wss://relay.damus.io"]

async def _fetch(url, pk, out):
    try:
        async with websockets.connect(url, open_timeout=8) as ws:
            await ws.send(json.dumps(["REQ", "b", {"kinds": [30078], "authors": [pk], "#d": ["bch-nostr-bind"], "limit": 5}]))
            while True:
                m = json.loads(await asyncio.wait_for(ws.recv(), 8))
                if m[0] == "EVENT": out.setdefault(m[2]["id"], (m[2], set()))[1].add(url)
                elif m[0] in ("EOSE", "CLOSED", "NOTICE"): break
    except Exception as e:
        print("relay err", url, type(e).__name__)

def lookup(pk):
    out = {}
    async def go(): await asyncio.gather(*[_fetch(u, pk, out) for u in RELAYS])
    asyncio.run(go())
    best = None
    for ev, seen in out.values():
        ok, addr, why = binding.verify_binding(ev)
        print(f"event {ev['id'][:12]} on {len(seen)} relays: {why} addr={addr}")
        if ok and (best is None or ev['created_at'] > best['created_at']): best = ev
    return best

async def _pub(ev):
    for u in RELAYS:
        try:
            async with websockets.connect(u, open_timeout=8) as ws:
                await ws.send(json.dumps(["EVENT", ev]))
                print(u, (await asyncio.wait_for(ws.recv(), 8))[:80])
        except Exception as e:
            print(u, "ERR", type(e).__name__)

if __name__ == "__main__":
    if sys.argv[1] == "demo":
        sk = os.urandom(32); d = int.from_bytes(os.urandom(32), "big") % bchsig.n
        ev = binding.make_binding(sk, d)
        print("local verify:", binding.verify_binding(ev))
        asyncio.run(_pub(ev))
        import time; time.sleep(2)
        b = lookup(ev["pubkey"])
        print("DISCOVERED:", bool(b), b and binding.verify_binding(b)[1])
        print("npub hex:", ev["pubkey"])
    else:
        b = lookup(sys.argv[2])
        print("RESULT:", binding.verify_binding(b) if b else "none found")
