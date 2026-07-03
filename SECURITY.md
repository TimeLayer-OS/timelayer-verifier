# Security Policy

## Reporting a Vulnerability

Email: **security@timelayer-os.com**. Do not open public issues for vulnerabilities.
We acknowledge reports within 72 hours and aim to provide a fix or mitigation
plan within 30 days.

## Scope

- `timelayer-verifier` (this repository)
- Receipt format: `cert.tlcert` (certificate) + `bundle.tlbundle` (bundle)
- Published keys: `pubkeys/epoch-2`

## Verifying releases

Check binaries against `SHA256SUMS-v2.0.0.txt` before use:

```bash
sha256sum -c SHA256SUMS-v2.0.0.txt      # Linux
shasum -a 256 -c SHA256SUMS-v2.0.0.txt  # macOS
```
