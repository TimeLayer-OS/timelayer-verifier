//! Authenticity layer for offline receipt verification.
//!
//! `tl_verify_public` (Layer A) recomputes every hash and checks structure/replay —
//! it is deliberately crypto-free, so a "VALID" from it proves only that a receipt is
//! self-consistent and tamper-evident, NOT that anyone signed it. This crate adds the
//! missing half: it extracts the Ed25519 cohort signatures embedded in the bundle,
//! binds them to the cert+bundle content, and requires a k-of-n quorum of DISTINCT
//! roster signers. Both checks must pass for an authentic VALID FINAL.
//!
//! It lives OUTSIDE Layer A precisely because it depends on asymmetric crypto
//! (`tl_cohort_sig` → ed25519-dalek), which the Layer-A no-crypto invariant forbids.

use tl_cohort_sig::proof::{verify_cohort, QuorumMode};
use tl_cohort_sig::receipt::SignedReceipt;
use tl_cohort_sig::roster::Roster;
use tl_finality::{decode_tlbundle, decode_tlcert, TLBundle, TLCert};
use tl_verify_public::{verify, PublicVerdict};

// Mirror tl_verify_public's diagnostic-stripping: the public build emits no
// mechanism vocabulary into the binary's string table.
#[cfg(feature = "public")]
macro_rules! lbl {
    ($s:expr) => {
        ""
    };
}
#[cfg(not(feature = "public"))]
macro_rules! lbl {
    ($s:expr) => {
        $s
    };
}

/// Outcome of the authenticity (signature) gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthnError {
    /// No signatures embedded at all → not an authentic receipt (vs. a wrong one).
    MissingSignature,
    /// Signatures present but malformed, not bound to this content, or below quorum.
    SignatureMismatch,
}

/// The authenticity gate. Extracts the embedded signed receipt, BINDS its signed core
/// fields to this cert+bundle's actual content (so a genuine signature cannot be
/// transplanted onto different content), then recomputes the root from content and
/// requires `k` valid Ed25519 signatures from distinct roster signers. Without this,
/// "VALID" proves only hash consistency — anyone could fabricate a self-consistent
/// receipt offline.
pub fn signature_check(
    cert: &TLCert,
    bundle: &TLBundle,
    roster: &Roster,
    k: usize,
    mode: QuorumMode,
) -> Result<(), AuthnError> {
    if bundle.signed_receipt.is_empty() {
        return Err(AuthnError::MissingSignature);
    }
    let receipt =
        SignedReceipt::decode(&bundle.signed_receipt).ok_or(AuthnError::SignatureMismatch)?;
    let core = &receipt.core;

    // Bind the signed core to THIS receipt's content. Every equality below ties the
    // signatures to a field a forger would have to change to repurpose a real
    // signature for different content; any mismatch ⇒ the signature is not over this
    // data, so it must not count.
    let peers: Vec<String> = cert.peers.iter().map(|p| p.0.clone()).collect();
    let peer_new_digests: Vec<[u8; 32]> = cert.peer_new_digests.iter().map(|d| d.0).collect();
    let mut expected_nonce = [0u8; 16];
    expected_nonce.copy_from_slice(&cert.interval_ref.0[..16]);
    let bound = core.doc_digest == cert.interval_ref.0
        && core.workflow_id == cert.cohort_id.0
        && core.step_index == cert.issued_at_pos
        && core.roster_epoch == roster.epoch
        && core.nonce == expected_nonce
        && core.meta_digest
            == tl_cohort_sig::meta_digest(
                &cert.local_digest.0,
                &cert.shadow_digest.0,
                cert.replay_params.as_slice(),
            )
        && core.ring_digest
            == tl_cohort_sig::ring_digest(&peers, &cert.ring_indices, &peer_new_digests);
    if !bound {
        return Err(AuthnError::SignatureMismatch);
    }

    // Recompute root FROM CONTENT and count valid signatures from distinct signers.
    if verify_cohort(core, &receipt.cohort_proof, roster, k, mode).valid {
        Ok(())
    } else {
        Err(AuthnError::SignatureMismatch)
    }
}

/// Full offline verification INCLUDING the Ed25519 cohort-signature quorum. This is
/// the gate the shipped verifier uses: the structural/hash checks (`verify`) AND the
/// authenticity check (`signature_check`) must both pass for VALID FINAL.
pub fn verify_with_roster(
    cert: &TLCert,
    bundle: Option<&TLBundle>,
    roster: &Roster,
    k: usize,
    mode: QuorumMode,
) -> PublicVerdict {
    match verify(cert, bundle) {
        PublicVerdict::VALID(status) => {
            let Some(bundle) = bundle else {
                return PublicVerdict::UNVERIFIABLE {
                    missing: lbl!("tlbundle").to_string(),
                };
            };
            match signature_check(cert, bundle, roster, k, mode) {
                Ok(()) => PublicVerdict::VALID(status),
                Err(AuthnError::MissingSignature) => PublicVerdict::UNVERIFIABLE {
                    missing: lbl!("signature").to_string(),
                },
                Err(AuthnError::SignatureMismatch) => PublicVerdict::DIVERGENT {
                    #[cfg(not(feature = "public"))]
                    reason: "SignatureMismatch".to_string(),
                    #[cfg(feature = "public")]
                    reason: String::new(),
                    location: lbl!("signature_check").to_string(),
                },
            }
        }
        other => other,
    }
}

/// Byte-level convenience wrapper for [`verify_with_roster`].
pub fn verify_bytes_with_roster(
    cert_bytes: &[u8],
    bundle_bytes: Option<&[u8]>,
    roster: &Roster,
    k: usize,
    mode: QuorumMode,
) -> PublicVerdict {
    let cert = match decode_tlcert(cert_bytes) {
        Ok(cert) => cert,
        Err(_) => {
            return PublicVerdict::UNVERIFIABLE {
                missing: lbl!("tlcert decode").to_string(),
            }
        }
    };
    let bundle = match bundle_bytes {
        Some(bytes) => match decode_tlbundle(bytes) {
            Ok(bundle) => Some(bundle),
            Err(_) => {
                return PublicVerdict::UNVERIFIABLE {
                    missing: lbl!("tlbundle decode").to_string(),
                }
            }
        },
        None => None,
    };
    verify_with_roster(&cert, bundle.as_ref(), roster, k, mode)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_canon_types::{CanonBytes, CohortId, NodeId};
    use tl_cohort_sig::proof::CohortSig;
    use tl_cohort_sig::roster::{NodeStatus, RosterEntry};
    use tl_cohort_sig::{
        core_fields_from_interval, keygen, sign_root, CoreFields, IntervalInputs, ALG_ED25519,
    };
    use tl_digest::Digest;
    use tl_finality::{CohortWitness, TLBUNDLE_SCHEMA, TLCERT_SCHEMA};
    use tl_receipts::ReceiptStatus;

    const EPOCH: u64 = 2;

    // n nodes, each its own operator op-i (distinct operators, by_operator-ready).
    fn mk_roster(n: usize) -> (Vec<[u8; 32]>, Roster) {
        let mut seeds = Vec::new();
        let mut entries = Vec::new();
        for i in 0..n {
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

    fn mk_cert(n: usize, cohort_id: &str) -> TLCert {
        let peers: Vec<NodeId> = (0..n).map(|i| NodeId(format!("tl-{}", i))).collect();
        let ring_indices: Vec<u64> = (0..n as u64).collect();
        let peer_new_digests: Vec<Digest> = (0..n).map(|i| Digest([(10 + i) as u8; 32])).collect();
        TLCert {
            schema: TLCERT_SCHEMA.to_string(),
            status: ReceiptStatus::FINAL,
            interval_ref: Digest([5; 32]),
            local_digest: Digest([20; 32]),
            shadow_digest: Digest([21; 32]),
            replay_params: CanonBytes(b"rp".to_vec()),
            cohort_id: CohortId(cohort_id.to_string()),
            peers,
            ring_indices,
            peer_new_digests,
            integrity_stamp: Digest([0; 32]),
            issued_at_pos: 7,
            bundle_ref: None,
        }
    }

    // CoreFields that bind to `cert` exactly as signature_check expects.
    fn core_for(cert: &TLCert) -> CoreFields {
        let peers: Vec<String> = cert.peers.iter().map(|p| p.0.clone()).collect();
        let digs: Vec<[u8; 32]> = cert.peer_new_digests.iter().map(|d| d.0).collect();
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&cert.interval_ref.0[..16]);
        core_fields_from_interval(&IntervalInputs {
            interval_ref: cert.interval_ref.0,
            prev_interval_ref: [0; 32],
            cohort_id: &cert.cohort_id.0,
            issued_at_pos: cert.issued_at_pos,
            issuer_node_id: &cert.peers[0].0,
            nonce,
            roster_epoch: EPOCH,
            local_digest: cert.local_digest.0,
            shadow_digest: cert.shadow_digest.0,
            replay_params: cert.replay_params.as_slice(),
            peers: &peers,
            ring_indices: &cert.ring_indices,
            peer_new_digests: &digs,
        })
    }

    fn sign_with(core: &CoreFields, seeds: &[[u8; 32]], who: &[usize]) -> Vec<CohortSig> {
        let root = core.root();
        who.iter()
            .map(|&i| CohortSig {
                node_id: format!("tl-{}", i),
                alg: ALG_ED25519,
                sig: sign_root(&seeds[i], &root),
            })
            .collect()
    }

    fn bundle_with(sig_bytes: Vec<u8>) -> TLBundle {
        TLBundle {
            schema: TLBUNDLE_SCHEMA.to_string(),
            interval_ref: Digest([5; 32]),
            history_fragment: Default::default(),
            replay_params: CanonBytes(b"rp".to_vec()),
            cohort_witness: CohortWitness {
                peers: vec![],
                ring_indices: vec![],
                peer_new_digests: vec![],
            },
            signed_receipt: sig_bytes,
            bundle_digest: Digest([0; 32]),
        }
    }

    #[test]
    fn honest_quorum_passes() {
        let (seeds, roster) = mk_roster(3);
        let cert = mk_cert(3, "trial");
        let receipt = SignedReceipt {
            core: core_for(&cert),
            cohort_proof: sign_with(&core_for(&cert), &seeds, &[0, 1]),
        };
        let bundle = bundle_with(receipt.encode());
        assert_eq!(
            signature_check(&cert, &bundle, &roster, 2, QuorumMode::ByOperator),
            Ok(())
        );
    }

    #[test]
    fn fabrication_from_scratch_is_rejected() {
        // Attacker has the roster (public keys) + algorithm but no private keys.
        let (_honest, roster) = mk_roster(3);
        let cert = mk_cert(3, "forged-doc");
        let core = core_for(&cert);
        let mut proof = Vec::new();
        for i in 0..3 {
            let (atk, _) = keygen().unwrap(); // fresh keypair NOT in the roster
            proof.push(CohortSig {
                node_id: format!("tl-{}", i),
                alg: ALG_ED25519,
                sig: sign_root(&atk, &core.root()),
            });
        }
        let bundle = bundle_with(SignedReceipt { core, cohort_proof: proof }.encode());
        assert_eq!(
            signature_check(&cert, &bundle, &roster, 2, QuorumMode::ByOperator),
            Err(AuthnError::SignatureMismatch)
        );
    }

    #[test]
    fn transplant_onto_different_content_is_rejected() {
        // A genuine signed receipt for doc A, pasted next to a cert for doc B.
        let (seeds, roster) = mk_roster(3);
        let cert_a = mk_cert(3, "doc-A");
        let receipt = SignedReceipt {
            core: core_for(&cert_a),
            cohort_proof: sign_with(&core_for(&cert_a), &seeds, &[0, 1]),
        };
        let bundle = bundle_with(receipt.encode()); // real signatures for doc-A
        let cert_b = mk_cert(3, "doc-B"); // different content
        assert_eq!(
            signature_check(&cert_b, &bundle, &roster, 2, QuorumMode::ByOperator),
            Err(AuthnError::SignatureMismatch)
        );
    }

    #[test]
    fn below_threshold_is_rejected() {
        let (seeds, roster) = mk_roster(3);
        let cert = mk_cert(3, "trial");
        let receipt = SignedReceipt {
            core: core_for(&cert),
            cohort_proof: sign_with(&core_for(&cert), &seeds, &[0]), // only 1 < k=2
        };
        let bundle = bundle_with(receipt.encode());
        assert_eq!(
            signature_check(&cert, &bundle, &roster, 2, QuorumMode::ByOperator),
            Err(AuthnError::SignatureMismatch)
        );
    }

    #[test]
    fn missing_signatures_is_unverifiable() {
        let (_seeds, roster) = mk_roster(3);
        let cert = mk_cert(3, "trial");
        let bundle = bundle_with(Vec::new()); // unsigned
        assert_eq!(
            signature_check(&cert, &bundle, &roster, 2, QuorumMode::ByOperator),
            Err(AuthnError::MissingSignature)
        );
    }
}
