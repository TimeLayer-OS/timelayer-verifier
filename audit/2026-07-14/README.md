# Self-audit — 2026-07-14 · verify it yourself

We audited our own repositories and site, filed **22 tickets**, and fixed every one.
Following our own method (Receipts + Brain): each ticket was sealed by **two TimeLayer
receipts** — one on entry, one on close — and the whole journal by a **master receipt**.
Nothing here is "trust us": every seal below verifies **offline** with the open-source
[timelayer-verifier](../../). This is the tool checking its own team's work.

## What's here
- `ledger.md` — 46 sealed events (22 tickets × open+close, +2), each with its sha256.
- `plan.md` · `TRACKER.md` · `REPORT.md` — the audit plan, status, and final report.
- `receipts/` — the 45 cert+bundle pairs (one per event), each an authentic network receipt.
- `ledger.master.tlcert` / `.tlbundle` — a single receipt sealing **this exact `ledger.md`**.

## Verify the whole journal in one command
```bash
# 1) the published journal is sealed by the network, byte-for-byte:
test "$(sha256sum ledger.md | cut -d' ' -f1)" = "030e3c5979cb06929b3a7869e05cfb9d5c9b94ee7dd706c1d9d1adc3a726a833" && echo "ledger sha OK"
timelayer-verifier verify ledger.master.tlcert ledger.master.tlbundle --expect 030e3c5979cb06929b3a7869e05cfb9d5c9b94ee7dd706c1d9d1adc3a726a833
# -> VALID FINAL
```

## Verify any single ticket seal
Each event's sha256 is in `ledger.md`. Bind the receipt to it:
```bash
# example: the close receipt for REP-010 (verifier --json)
SHA=$(grep 'REP-010.close' ledger.md | grep -o 'sha256=[0-9a-f]*' | cut -d= -f2)
timelayer-verifier verify receipts/REP-010.close.tlcert receipts/REP-010.close.tlbundle --expect $SHA
# -> VALID FINAL
```

Or just confirm every receipt is an authentic quorum-signed FINAL receipt:
```bash
for c in receipts/*.tlcert; do timelayer-verifier verify "$c" "${c%.tlcert}.tlbundle" >/dev/null && echo "OK $c"; done
```

**22 tickets, 45 receipts, one master seal — all checkable by anyone, offline.**
