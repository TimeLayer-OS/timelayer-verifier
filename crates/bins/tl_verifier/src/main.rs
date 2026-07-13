use std::env;
use std::fs;
use std::path::Path;

use tl_cohort_sig::proof::QuorumMode;
use tl_cohort_sig::roster::{parse_roster, Roster};
use tl_digest::digest_bytes;
use tl_finality::{decode_tlcert, interval_ref_from_digests};
use tl_receipts::ReceiptStatus;
use tl_verify_authn::verify_bytes_with_roster;
use tl_verify_public::PublicVerdict;


const MAX_CERT_BYTES: u64 = 1024 * 1024;
const MAX_BUNDLE_BYTES: u64 = 16 * 1024 * 1024;

/// The deployed cohort trust anchor, compiled into the binary so offline
/// verification needs no external files. This mirrors the network's published
/// roster.txt; the quorum policy (k and mode) below matches the live node config.
const EMBEDDED_ROSTER: &str = include_str!("roster_epoch2.txt");
/// Live quorum threshold (k) — confirmed from the running node config.
const QUORUM_K: usize = 2;

/// Parse the compiled-in roster. Infallible in practice (the asset is a fixed,
/// in-tree file validated at build/test time); we surface a clear message if a
/// future edit breaks its format rather than silently accepting nothing.
fn embedded_roster() -> Option<Roster> {
    parse_roster(EMBEDDED_ROSTER)
}

#[derive(Clone, Debug, Default)]
pub struct VerifierCli;


const HELP: &str = "\
timelayer-verifier — offline verification of TimeLayer receipts

USAGE:
  timelayer-verifier verify <cert.tlcert> <bundle.tlbundle> [--expect <hex>] [--json]
  timelayer-verifier --version | -V
  timelayer-verifier --help | -h

VERIFY:
  Recomputes the receipt's BLAKE3 commitment, checks the Ed25519 quorum against
  the compiled-in operator roster, and requires status FINAL. No network, no key
  server, no external files — the receipt is self-contained.

  --expect <hex>   Bind the check to a specific subject: the receipt must attest
                   exactly this digest (hex of your action/document). A valid but
                   unrelated receipt is refused (receipt-transplant defence).
  --json           Emit one JSON object to stdout instead of a text verdict.

VERDICTS:
  VALID FINAL    authentic, complete, and (with --expect) about that subject
  NOT VALID      forged, tampered, divergent, or below quorum
  UNVERIFIABLE   undecodable input, malformed --expect, or --expect mismatch

STREAMS & EXIT:
  Text mode: VALID FINAL -> stdout; NOT VALID / UNVERIFIABLE -> stderr.
  JSON mode: the object always goes to stdout.
  Exit code: 0 = VALID FINAL, 1 = anything else (fail-closed — check it first).

JSON SHAPE:
  {\"result\":\"valid_final|not_valid|unverifiable\",\"reason\":\"...\",
   \"expect_matched\":true|false|null,\"verifier_version\":\"x.y.z\"}";

/// Machine-readable outcome of a verify, independent of output format.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyResult {
    ValidFinal,
    NotValid,
    Unverifiable,
}

impl VerifyResult {
    fn key(&self) -> &'static str {
        match self {
            Self::ValidFinal => "valid_final",
            Self::NotValid => "not_valid",
            Self::Unverifiable => "unverifiable",
        }
    }
    fn text(&self) -> &'static str {
        match self {
            Self::ValidFinal => "VALID FINAL",
            Self::NotValid => "NOT VALID",
            Self::Unverifiable => "UNVERIFIABLE",
        }
    }
    fn exit(&self) -> i32 {
        if matches!(self, Self::ValidFinal) { 0 } else { 1 }
    }
}

pub struct Verdict {
    pub result: VerifyResult,
    pub reason: String,
    /// Some(true/false) when --expect was supplied; None otherwise.
    pub expect_matched: Option<bool>,
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

fn emit(verdict: &Verdict, json: bool) -> i32 {
    if json {
        let em = match verdict.expect_matched {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        };
        println!(
            "{{\"result\":\"{}\",\"reason\":\"{}\",\"expect_matched\":{},\"verifier_version\":\"{}\"}}",
            verdict.result.key(),
            json_escape(&verdict.reason),
            em,
            env!("CARGO_PKG_VERSION"),
        );
    } else if matches!(verdict.result, VerifyResult::ValidFinal) {
        println!("{}", verdict.result.text());
    } else if verdict.reason.is_empty() {
        eprintln!("{}", verdict.result.text());
    } else {
        eprintln!("{} {}", verdict.result.text(), verdict.reason);
    }
    verdict.result.exit()
}

pub fn run_verifier(args: &[String]) -> i32 {
    match args.get(1).map(String::as_str) {
        Some("--version") | Some("-V") => {
            println!("{}", env!("CARGO_PKG_VERSION"));
            0
        }
        Some("--help") | Some("-h") | Some("help") => {
            println!("{HELP}");
            0
        }
        Some("verify") => {
            // Flexible flag parse: positional cert/bundle in order; --expect <hex>; --json.
            let rest = &args[2..];
            let mut positional: Vec<&String> = Vec::new();
            let mut expect: Option<&String> = None;
            let mut json = false;
            let mut i = 0;
            while i < rest.len() {
                match rest[i].as_str() {
                    "--json" => json = true,
                    "--expect" => {
                        if i + 1 >= rest.len() {
                            return emit(&Verdict {
                                result: VerifyResult::Unverifiable,
                                reason: "--expect requires a hex digest".into(),
                                expect_matched: None,
                            }, json);
                        }
                        expect = Some(&rest[i + 1]);
                        i += 1;
                    }
                    other if other.starts_with("--") => {
                        eprintln!("unknown flag: {other}");
                        return 1;
                    }
                    _ => positional.push(&rest[i]),
                }
                i += 1;
            }
            if positional.len() != 2 {
                eprintln!(
                    "usage: timelayer-verifier verify <cert.tlcert> <bundle.tlbundle> [--expect <hex>] [--json]"
                );
                return 1;
            }
            let verdict = evaluate_files(
                Path::new(positional[0]),
                Path::new(positional[1]),
                expect.map(String::as_str),
            );
            emit(&verdict, json)
        }
        _ => {
            eprintln!(
                "usage: timelayer-verifier verify <cert.tlcert> <bundle.tlbundle> [--expect <hex>] [--json]"
            );
            eprintln!("try: timelayer-verifier --help");
            1
        }
    }
}

/// Confirm the certificate actually notarizes `expected` (the raw document digest the
/// caller sent as action_hex). The leaf the network binds is
/// `digest_bytes(issued_at_pos_be8 ++ action)`, committed via the certificate's
/// interval_ref — so we recompute it and compare. This is the cryptographic binding:
/// a valid-but-unrelated receipt no longer passes for arbitrary content.
fn cert_attests(cert: &[u8], expected: &[u8]) -> bool {
    let Ok(decoded) = decode_tlcert(cert) else {
        return false;
    };
    let mut material = decoded.issued_at_pos.to_be_bytes().to_vec();
    material.extend_from_slice(expected);
    interval_ref_from_digests(&[digest_bytes(&material)]) == decoded.interval_ref
}

/// Decode a hex string into bytes; None on any non-hex input or odd length.
fn parse_expect_hex(value: &str) -> Option<Vec<u8>> {
    if value.len() % 2 != 0 {
        return None;
    }
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(value.len() / 2);
    let mut idx = 0;
    while idx < bytes.len() {
        let hi = (bytes[idx] as char).to_digit(16)?;
        let lo = (bytes[idx + 1] as char).to_digit(16)?;
        out.push(((hi << 4) | lo) as u8);
        idx += 2;
    }
    Some(out)
}

fn read_or_report(path: &Path, max_bytes: u64) -> Option<Vec<u8>> {
    match read_limited(path, max_bytes) {
        Ok(bytes) => Some(bytes),
        Err(error) => {
            eprintln!("{}", error);
            None
        }
    }
}

fn evaluate_files(cert_path: &Path, bundle_path: &Path, expect_hex: Option<&str>) -> Verdict {
    let Some(roster) = embedded_roster() else {
        return Verdict {
            result: VerifyResult::Unverifiable,
            reason: "embedded roster is malformed".into(),
            expect_matched: None,
        };
    };
    evaluate_files_with_policy(
        cert_path,
        bundle_path,
        expect_hex,
        &roster,
        QUORUM_K,
        QuorumMode::ByOperator,
    )
}

/// Core of the offline verify command, parameterized by the quorum policy
/// (roster + k + mode). Returns a structured `Verdict` (format-agnostic).
/// Production wiring passes the compiled-in trust anchor; the binary integration
/// tests pass a controlled test roster so the honest path can be exercised
/// end-to-end without the operators' private keys.
fn evaluate_files_with_policy(
    cert_path: &Path,
    bundle_path: &Path,
    expect_hex: Option<&str>,
    roster: &Roster,
    k: usize,
    mode: QuorumMode,
) -> Verdict {
    let want_expect = expect_hex.is_some();
    let unresolved = || if want_expect { Some(false) } else { None };
    let Some(cert) = read_or_report(cert_path, MAX_CERT_BYTES) else {
        return Verdict { result: VerifyResult::Unverifiable, reason: "cannot read cert".into(), expect_matched: unresolved() };
    };
    let Some(bundle) = read_or_report(bundle_path, MAX_BUNDLE_BYTES) else {
        return Verdict { result: VerifyResult::Unverifiable, reason: "cannot read bundle".into(), expect_matched: unresolved() };
    };
    match verify_bytes_with_roster(&cert, Some(&bundle), roster, k, mode) {
        PublicVerdict::VALID(ReceiptStatus::FINAL) => {
            if let Some(hex) = expect_hex {
                let Some(expected) = parse_expect_hex(hex) else {
                    return Verdict { result: VerifyResult::Unverifiable, reason: "--expect must be a hex digest".into(), expect_matched: Some(false) };
                };
                if !cert_attests(&cert, &expected) {
                    return Verdict { result: VerifyResult::Unverifiable, reason: "receipt does not attest the expected digest".into(), expect_matched: Some(false) };
                }
                return Verdict { result: VerifyResult::ValidFinal, reason: String::new(), expect_matched: Some(true) };
            }
            Verdict { result: VerifyResult::ValidFinal, reason: String::new(), expect_matched: None }
        }
        _ => Verdict { result: VerifyResult::NotValid, reason: String::new(), expect_matched: unresolved() },
    }
}

/// Back-compat wrapper used by the integration tests: exit code only.
#[cfg(test)]
fn verify_files_with_policy(
    cert_path: &Path,
    bundle_path: &Path,
    expect_hex: Option<&str>,
    roster: &Roster,
    k: usize,
    mode: QuorumMode,
) -> i32 {
    evaluate_files_with_policy(cert_path, bundle_path, expect_hex, roster, k, mode)
        .result
        .exit()
}

/// Offline verification proves the presented history is internally consistent
/// and reproducible. The online cross-check (compiled only into the internal
/// `live` build) is not part of the public offline tool.










fn read_limited(path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if metadata.len() > max_bytes {
        return Err(format!(
            "{} exceeds maximum size {} bytes",
            path.display(),
            max_bytes
        ));
    }
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    if bytes.len() as u64 > max_bytes {
        return Err(format!(
            "{} exceeds maximum size {} bytes",
            path.display(),
            max_bytes
        ));
    }
    Ok(bytes)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let code = run_verifier(&args);
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    //! End-to-end proof of the authenticity gate through the binary's real verify
    //! codepath (`verify_files_with_policy`). We mint a structurally valid cert+bundle
    //! and sign it with a CONTROLLED test roster (the live roster's private keys are
    //! held by the operators and are deliberately not here), then assert:
    //!   honest quorum            -> exit 0 (VALID FINAL)
    //!   fabricated (wrong keys)  -> exit 1 (NOT VALID)
    //!   transplanted signature   -> exit 1 (NOT VALID)
    //!   below threshold          -> exit 1 (NOT VALID)
    //!   unsigned (current format)-> exit 1 (NOT VALID)
    //! Plus a check that the compiled-in production roster parses to the live policy.
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    use tl_canon_types::{CanonBytes, CohortId, IntervalId, NodeId, Tick};
    use tl_cohort::{CohortProof, QuorumThreshold};
    use tl_cohort_sig::proof::CohortSig;
    use tl_cohort_sig::receipt::SignedReceipt;
    use tl_cohort_sig::roster::{NodeStatus, RosterEntry};
    use tl_cohort_sig::{
        core_fields_from_interval, keygen, sign_root, IntervalInputs, ALG_ED25519,
    };
    use tl_digest::Digest;
    use tl_finality::{
        encode_tlbundle, encode_tlcert, export_bundle, export_certificate, interval_history_fragment,
        tlcert_integrity_stamp, CohortWitness, FinalFact, FinalizationInterval,
    };
    use tl_shadow::{run_shadow, ShadowExec, ShadowMode};

    const EPOCH: u64 = 2;
    static SEQ: AtomicU32 = AtomicU32::new(0);

    // Who signs the minted receipt.
    enum Sign<'a> {
        Honest,                // k=2 distinct roster operators -> valid
        OneOnly,               // 1 signer -> below by_operator k=2
        Attacker,              // 2 sigs from keys NOT in the roster
        Custom(&'a [u8]),      // paste a foreign signed_receipt blob (transplant)
        Unsigned,              // empty signed_receipt (the pre-fix format)
    }

    struct Minted {
        cert_path: std::path::PathBuf,
        bundle_path: std::path::PathBuf,
        signed_receipt: Vec<u8>,
    }

    fn unique_dir(tag: &str) -> std::path::PathBuf {
        let n = SEQ.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("tlv_{}_{}_{}", tag, std::process::id(), n));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    // A roster of 3 distinct-operator nodes (by_operator-ready). Returns seeds + roster.
    fn test_roster() -> (Vec<[u8; 32]>, Roster) {
        let mut seeds = Vec::new();
        let mut entries = Vec::new();
        for i in 0..3 {
            let (seed, pk) = keygen().unwrap();
            seeds.push(seed);
            entries.push(RosterEntry {
                node_id: format!("tl-{}", i),
                pubkey: pk,
                alg: ALG_ED25519,
                operator: format!("op-{}", i),
                region: "EU".into(),
                status: NodeStatus::Active,
                valid_from: 0,
                valid_to: None,
            });
        }
        (seeds, Roster { epoch: EPOCH, entries })
    }

    // Mint a structurally valid cert+bundle for `content`, signed per `sign`.
    fn mint(tag: &str, content: &[u8], seeds: &[[u8; 32]], sign: Sign) -> Minted {
        let peers: Vec<NodeId> = (0..3).map(|i| NodeId(format!("tl-{}", i))).collect();
        let peer_strs: Vec<String> = peers.iter().map(|p| p.0.clone()).collect();
        let ring_indices: Vec<u64> = vec![0, 1, 2];
        let peer_new_digests: Vec<Digest> = vec![Digest([10; 32]), Digest([11; 32]), Digest([12; 32])];
        let pnd_raw: Vec<[u8; 32]> = peer_new_digests.iter().map(|d| d.0).collect();
        let replay_params = CanonBytes(b"rp".to_vec());

        // History fragment uniquely seeded by `content` so different content => a
        // different local_digest (and so a different signed root). This is what makes
        // a transplant detectable.
        let seed_digest = digest_bytes(content);
        let hf = interval_history_fragment(&[seed_digest]);
        let local = Digest::from(tl_rw_core::replay_fragment(&hf).unwrap());
        let shadow_raw = run_shadow(&ShadowExec { mode: ShadowMode::PS }, &hf)
            .unwrap()
            .shadow_digest
            .0;
        let shadow = Digest::from(shadow_raw);

        let issued_at_pos = 7u64;
        let cohort_id = CohortId("trial".into());

        // CoreFields bound to exactly this content (mirrors what the node signs and
        // what tl_verify_authn::signature_check rebinds against).
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&local.0[..16]);
        let core = core_fields_from_interval(&IntervalInputs {
            interval_ref: local.0,
            prev_interval_ref: [0; 32],
            cohort_id: &cohort_id.0,
            issued_at_pos,
            issuer_node_id: &peer_strs[0],
            nonce,
            roster_epoch: EPOCH,
            local_digest: local.0,
            shadow_digest: shadow.0,
            replay_params: replay_params.as_slice(),
            peers: &peer_strs,
            ring_indices: &ring_indices,
            peer_new_digests: &pnd_raw,
        });
        let root = core.root();

        let signed_receipt = match sign {
            Sign::Unsigned => Vec::new(),
            Sign::Custom(bytes) => bytes.to_vec(),
            Sign::Honest | Sign::OneOnly => {
                let who: &[usize] = if matches!(sign, Sign::Honest) { &[0, 1] } else { &[0] };
                let proof: Vec<CohortSig> = who
                    .iter()
                    .map(|&i| CohortSig {
                        node_id: format!("tl-{}", i),
                        alg: ALG_ED25519,
                        sig: sign_root(&seeds[i], &root),
                    })
                    .collect();
                SignedReceipt { core: core.clone(), cohort_proof: proof }.encode()
            }
            Sign::Attacker => {
                let mut proof = Vec::new();
                for i in 0..2 {
                    let (atk, _) = keygen().unwrap(); // not in the roster
                    proof.push(CohortSig {
                        node_id: format!("tl-{}", i),
                        alg: ALG_ED25519,
                        sig: sign_root(&atk, &root),
                    });
                }
                SignedReceipt { core: core.clone(), cohort_proof: proof }.encode()
            }
        };

        let cohort_proof = CohortProof {
            cohort_id: cohort_id.clone(),
            interval_id: IntervalId(1),
            member_ids: peers.clone(),
            witness_digests: vec![],
            ring_indices: ring_indices.clone(),
            peer_new_digests: peer_new_digests.clone(),
            threshold: QuorumThreshold(2),
            proof_digest: Default::default(),
        };
        let fact = FinalFact {
            local_digest: local.into(),
            shadow_digest: shadow.into(),
            proof_of_replay: shadow.into(),
            cohort_proof,
            integrity_stamp: Digest::default(),
            issued_at_pos,
            replay_params: replay_params.clone(),
        };
        let interval = FinalizationInterval {
            interval_id: IntervalId(1),
            start: Tick(0),
            end: Tick(issued_at_pos),
            interval_ref: local, // export_certificate sets cert.interval_ref = local too
            history_fragment: hf,
            replay_params: replay_params.clone(),
            cohort_witness: CohortWitness {
                peers,
                ring_indices,
                peer_new_digests,
            },
            signed_receipt: signed_receipt.clone(),
        };

        // Same composition the node runtime uses (export_certificate_bundle).
        let bundle = export_bundle(interval);
        let mut cert = export_certificate(fact);
        cert.bundle_ref = Some(bundle.bundle_digest);
        cert.integrity_stamp = tlcert_integrity_stamp(&cert);

        // Allow dumping fixtures to a stable path so the literal CLI binary can be
        // driven against them (test-only; no effect on the shipped binary).
        let dir = match std::env::var("TLV_DUMP") {
            Ok(base) => {
                let d = std::path::PathBuf::from(base).join(tag);
                fs::create_dir_all(&d).unwrap();
                d
            }
            Err(_) => unique_dir(tag),
        };
        let cert_path = dir.join("cert.tlcert");
        let bundle_path = dir.join("bundle.tlbundle");
        fs::write(&cert_path, encode_tlcert(&cert)).unwrap();
        fs::write(&bundle_path, encode_tlbundle(&bundle)).unwrap();
        Minted { cert_path, bundle_path, signed_receipt }
    }

    fn run(m: &Minted, roster: &Roster) -> i32 {
        verify_files_with_policy(
            &m.cert_path,
            &m.bundle_path,
            None,
            roster,
            QUORUM_K,
            QuorumMode::ByOperator,
        )
    }

    #[test]
    fn honest_quorum_is_valid_final() {
        let (seeds, roster) = test_roster();
        let m = mint("honest", b"doc-A", &seeds, Sign::Honest);
        assert_eq!(run(&m, &roster), 0, "honest k-of-n quorum must verify");
    }

    #[test]
    fn unsigned_receipt_is_not_valid() {
        // The pre-fix bundle format (empty attestation) must now be rejected: this is
        // the exact vulnerability being closed — hash-consistent but not authenticated.
        let (seeds, roster) = test_roster();
        let m = mint("unsigned", b"doc-A", &seeds, Sign::Unsigned);
        assert_eq!(run(&m, &roster), 1, "unsigned receipt must NOT be valid");
    }

    #[test]
    fn fabricated_signatures_are_not_valid() {
        let (seeds, roster) = test_roster();
        let m = mint("fabricated", b"doc-A", &seeds, Sign::Attacker);
        assert_eq!(run(&m, &roster), 1, "non-roster keys must NOT be valid");
    }

    #[test]
    fn below_threshold_is_not_valid() {
        let (seeds, roster) = test_roster();
        let m = mint("below", b"doc-A", &seeds, Sign::OneOnly);
        assert_eq!(run(&m, &roster), 1, "one signer (< k=2) must NOT be valid");
    }

    #[test]
    fn transplanted_signature_is_not_valid() {
        // A genuine signature for doc-A, pasted into a receipt for doc-B.
        let (seeds, roster) = test_roster();
        let honest_a = mint("transplant_src", b"doc-A", &seeds, Sign::Honest);
        let m = mint("transplant_dst", b"doc-B", &seeds, Sign::Custom(&honest_a.signed_receipt));
        assert_eq!(run(&m, &roster), 1, "signature bound to other content must NOT be valid");
    }

    #[test]
    fn embedded_production_roster_matches_live_policy() {
        let roster = embedded_roster().expect("compiled-in roster must parse");
        assert_eq!(roster.epoch, 2, "live roster epoch");
        assert_eq!(roster.entries.len(), 11, "11 live nodes tl-0..tl-10");
        assert_eq!(QUORUM_K, 2, "live quorum_threshold");
        let mut ops: Vec<String> = roster.entries.iter().map(|e| e.operator.clone()).collect();
        ops.sort();
        ops.dedup();
        assert_eq!(ops, vec!["operator-1", "operator-2", "operator-3"], "anonymized operator set (public roster)");
    }
}
