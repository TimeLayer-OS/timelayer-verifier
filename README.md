# TimeLayer — offline verifier

A small, self-contained tool that **verifies a TimeLayer signed receipt offline** — with no
connection to the network — by checking its cohort signatures against the public roster of node keys.

> **Status: test network.** TimeLayer is currently running as a test network while the mechanisms are
> polished. This verifier checks that a receipt was signed by **≥ k distinct keys from the roster**.
> It does **not** by itself prove the keys are held by unrelated independent operators — that comes
> when real, independent operators run the nodes. **No "unforgeable" guarantee is claimed yet.**

## What it checks

A receipt commits to a 32-byte **root** = `BLAKE3(domain ‖ canonical_fields)` over the receipt's
content (document digest, position in the causal chain, issuer, a nonce, the roster epoch, the
replay/shadow proof digest, and the cohort ring digest). Each cohort node **signs that root** with its
own Ed25519 key. The verifier:

1. **recomputes the root from the content** (never trusts a root supplied in the receipt);
2. checks **≥ k valid Ed25519 signatures** from **distinct** signers that are **active in the roster**
   at the receipt's epoch.

This is what closes *fabrication from scratch*: anyone with the public keys and the open algorithm can
recompute every hash, but **cannot produce k real signatures without the nodes' private keys.**

- Signatures: **Ed25519** (RFC 8032). Hash: **BLAKE3**. Serialization: explicit length-prefixed fields.
- The algorithm is fully open on purpose (Kerckhoffs): security rests on the private keys, not secrecy.

## Build

```bash
cargo build --release
# binary at target/release/timelayer-verifier
# a prebuilt Linux x86-64 binary is in bin/
```

## Use

```bash
timelayer-verifier verify <receipt.tlsig> <roster.txt> <k> [by_node|by_operator]
```

- `<receipt.tlsig>` — the signed receipt.
- `<roster.txt>` — the public roster (one line per node:
  `node_id|pubkey_hex|alg|operator|region|status|valid_from|valid_to`, with a leading `epoch=N`).
- `<k>` — required number of distinct signers.
- mode — `by_node` (distinct nodes) or `by_operator` (distinct operators; one operator = one vote).

Exit code `0` = VALID, `1` = NOT VALID.

## Test vectors (`testvectors/`)

```bash
timelayer-verifier verify testvectors/valid.tlsig  testvectors/roster.txt 6 by_operator   # -> VALID
timelayer-verifier verify testvectors/forged.tlsig testvectors/roster.txt 6 by_operator   # -> NOT VALID
```

`forged.tlsig` is a fabricated receipt signed by keys that are **not** on the roster — the canonical
"fabrication from scratch" attempt — and it verifies as **NOT VALID**. Regenerate with
`timelayer-verifier testvec gen <dir>`.

## License

MIT — see `LICENSE`.
