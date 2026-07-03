# TimeLayer — offline verifier

**English** · [Русский](README.ru.md)

A small, self-contained tool that **verifies a TimeLayer receipt offline** — with no network,
no roster lookup, and no trust in us. A receipt is a **pair of files** that carries everything
needed to check it; the verifier recomputes every hash and checks the signatures locally.

```
timelayer-verifier verify cert.tlcert bundle.tlbundle
# -> VALID FINAL        (exit 0)  authentic and complete
# -> NOT VALID / UNVERIFIABLE (exit 1)  forged, divergent, or undecodable
```

> **Status: live network.** Each receipt is signed by an **Ed25519 quorum of independent
> operators** — no single node (including us) can issue one alone. The verification algorithm
> is fully open (Kerckhoffs's principle): security rests on the operators' **private keys**,
> never on secrecy of the code. An external security audit is on the roadmap — until then we
> don't claim "unforgeable," only "signed by a quorum and checkable offline."

## What it checks

A receipt is the pair `cert.tlcert` (the certificate) + `bundle.tlbundle` (its supporting
evidence). The verifier:

1. **recomputes the root** = `BLAKE3(domain ‖ canonical_fields)` from the receipt's own content
   (document digest, position in the causal chain, issuer, nonce, the replay/shadow proof
   digest, the cohort digest) — it never trusts a root handed to it;
2. checks the **Ed25519 quorum signatures** over that root from the cohort that signed it;
3. confirms the receipt is **FINAL** (complete, not a partial/intermediate state).

If everything lines up it prints `VALID FINAL`. Any mismatch — a flipped byte, a missing
signature, a fabricated cert — prints `NOT VALID` (or `UNVERIFIABLE` for undecodable input) and exits non-zero.

- Signatures: **Ed25519** (RFC 8032). Hash: **BLAKE3**. Serialization: explicit length-prefixed fields.
- **Offline and self-contained:** no roster file, no network call, no key server. You can pull the
  network cable and it still works.

## Download

Pre-built binaries are on the [Releases page](https://github.com/TimeLayer-OS/timelayer-verifier/releases/latest):

| Platform | File |
|----------|------|
| Linux x86-64 | `timelayer-verifier-linux-amd64` |
| macOS Apple Silicon (M1/M2/M3) | `timelayer-verifier-macos-arm64` |
| macOS Intel | `timelayer-verifier-macos-x86_64` |
| Windows x86-64 | `timelayer-verifier-windows-amd64.exe` |

**macOS / Linux — make executable after download:**
```bash
chmod +x timelayer-verifier-*
```
**macOS — first run**: right-click the binary → Open → Open (to bypass Gatekeeper on unsigned binaries).

## Build from source

```bash
cargo build --release
# binary at target/release/timelayer-verifier
```

The source here is the **complete** offline verifier: the receipt/cohort/finality crates it
needs are vendored in `crates/`. There is no hidden dependency — what verifies your receipt is
exactly what you can read and compile.

## Use

```bash
timelayer-verifier verify <cert.tlcert> <bundle.tlbundle>
```

Exit code `0` = `VALID FINAL`, `1` = `NOT VALID` / `UNVERIFIABLE`.

## Test vectors (`testvectors/`)

```bash
timelayer-verifier verify testvectors/valid/cert.tlcert  testvectors/valid/bundle.tlbundle   # -> VALID FINAL
timelayer-verifier verify testvectors/forged/cert.tlcert testvectors/forged/bundle.tlbundle  # -> NOT VALID
```

`forged/` pairs the cert of one real signed receipt with the bundle of another — a decodable
but divergent transplant, the canonical forgery attempt — and it verifies as **NOT VALID**.
Both vectors are real `tlbundle/2` receipts minted by the live network.

## Operator key transparency (`pubkeys/`)

`pubkeys/epoch-2/` publishes the current operators' Ed25519 public keys so anyone can
independently see which keys are in the network. **The verifier does not need these files** —
a receipt is self-contained — they are published purely for transparency and cross-checking.

## Threat model

- **What a receipt proves.** That this `cert.tlcert` + `bundle.tlbundle` is internally
  consistent (BLAKE3 root), carries a `FINAL` marker, and was signed by a quorum of the
  published operator keys (Ed25519) over exactly this content — checkable offline, with no
  network, key server, or roster lookup.
- **What it does not prove.** The *truth* of the content. A receipt proves a quorum attested to
  this specific document, not that the document's claims are correct.
- **Operator key compromise.** One key is not enough. `VALID FINAL` requires a quorum of
  signatures from *distinct* independent operators, so a single compromised operator key cannot
  forge a receipt. Keys are rotated by publishing a new epoch.
- **Quorum unavailable.** Fail-closed: if a quorum cannot sign, no receipt is issued — you get
  none, never a false one. Receipts already issued stay verifiable offline forever (self-contained).
- **Receipt loss.** The receipt is what you keep; the network stores none of your content
  (only a hash ever leaves you). If a receipt is lost, re-notarize the action to obtain a new one.

## License

Apache 2.0 — see [`LICENSE`](LICENSE).
