use tl_canon_types::DigestRef;
use tl_cohort::{quorum_reached, CohortConfig, CohortProof};
use tl_digest::Digest;
use tl_finality::{
    cert_cohort_digest, decode_tlbundle, decode_tlcert, tlcert_integrity_stamp,
    verify_inclusion_proof, IntervalInclusionProof, TLBundle, TLCert, TemporalCertificate,
    TLBUNDLE_SCHEMA, TLCERT_SCHEMA,
};
use tl_receipts::ReceiptStatus;
use tl_rw_core::{replay_fragment, HistoryFragment, TemporalContext};
use tl_shadow::{compare_shadow_digest, run_shadow, ShadowDigest, ShadowExec, ShadowMode};

// Diagnostic labels are useful internally but reveal mechanism vocabulary, so the
// public (offline) build compiles them out: `lbl!("x")` becomes "" and never reaches
// the binary's string table. The default build keeps the full diagnostics.
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

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PublicVerifier {
    pub config: PublicVerificationConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationBundle {
    pub history_fragment: HistoryFragment,
    pub temporal_context: TemporalContext,
    pub cohort_proof: Option<CohortProof>,
    pub cohort_witnesses: Vec<DigestRef>,
    pub declared_status: ReceiptStatus,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct PublicVerificationConfig {
    pub cohort_config: CohortConfig,
}

#[allow(non_camel_case_types)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicVerdict {
    VALID(ReceiptStatus),
    DIVERGENT { reason: String, location: String },
    UNVERIFIABLE { missing: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicVerifyError {
    MissingData,
    DigestMismatch,
    ReplayMismatch,
    CohortMismatch,
    StatusMismatch,
}

pub fn recompute_digest(
    certificate: &TemporalCertificate,
    bundle: &VerificationBundle,
) -> Result<(), PublicVerifyError> {
    let digest =
        replay_fragment(&bundle.history_fragment).map_err(|_| PublicVerifyError::MissingData)?;
    if digest == certificate.final_fact.local_digest {
        Ok(())
    } else {
        Err(PublicVerifyError::DigestMismatch)
    }
}

pub fn replay_check(
    certificate: &TemporalCertificate,
    bundle: &VerificationBundle,
) -> Result<(), PublicVerifyError> {
    let exec = ShadowExec {
        mode: ShadowMode::PS,
    };
    let result =
        run_shadow(&exec, &bundle.history_fragment).map_err(|_| PublicVerifyError::MissingData)?;
    compare_shadow_digest(
        &certificate.final_fact.shadow_digest,
        &ShadowDigest(result.shadow_digest.0),
    )
    .map_err(|_| PublicVerifyError::ReplayMismatch)
}

pub fn cohort_check(
    config: &PublicVerificationConfig,
    certificate: &TemporalCertificate,
    bundle: &VerificationBundle,
) -> Result<(), PublicVerifyError> {
    let proof = bundle
        .cohort_proof
        .as_ref()
        .ok_or(PublicVerifyError::MissingData)?;
    if proof.proof_digest != certificate.final_fact.cohort_proof.proof_digest {
        return Err(PublicVerifyError::CohortMismatch);
    }
    if !quorum_reached(&config.cohort_config, proof.witness_digests.len()) {
        return Err(PublicVerifyError::CohortMismatch);
    }
    if proof.member_ids.len() < proof.threshold.0 {
        return Err(PublicVerifyError::CohortMismatch);
    }
    Ok(())
}

pub fn monotonicity_check(
    certificate: &TemporalCertificate,
    bundle: &VerificationBundle,
) -> Result<(), PublicVerifyError> {
    if bundle.declared_status > certificate.status {
        return Err(PublicVerifyError::StatusMismatch);
    }
    match bundle.declared_status {
        ReceiptStatus::FINAL => {
            if bundle.cohort_proof.is_none() {
                Err(PublicVerifyError::MissingData)
            } else {
                Ok(())
            }
        }
        ReceiptStatus::SHADOWED => {
            if certificate.final_fact.shadow_digest == DigestRef::default() {
                Err(PublicVerifyError::MissingData)
            } else {
                Ok(())
            }
        }
        ReceiptStatus::LOCAL => Ok(()),
    }
}

pub fn verify_certificate(
    verifier: &PublicVerifier,
    certificate: &TemporalCertificate,
    bundle: &VerificationBundle,
) -> PublicVerdict {
    if let Err(error) = recompute_digest(certificate, bundle) {
        return verdict_from_error(error, lbl!("recompute_digest"));
    }
    if let Err(error) = replay_check(certificate, bundle) {
        return verdict_from_error(error, lbl!("replay_check"));
    }
    if let Err(error) = cohort_check(&verifier.config, certificate, bundle) {
        return verdict_from_error(error, lbl!("cohort_check"));
    }
    if let Err(error) = monotonicity_check(certificate, bundle) {
        return verdict_from_error(error, lbl!("monotonicity_check"));
    }
    PublicVerdict::VALID(bundle.declared_status)
}

pub fn verify(cert: &TLCert, bundle: Option<&TLBundle>) -> PublicVerdict {
    if cert.schema != TLCERT_SCHEMA {
        return PublicVerdict::UNVERIFIABLE {
            missing: "tlcert schema".to_string(),
        };
    }
    if let Some(bundle) = bundle {
        if bundle.schema != TLBUNDLE_SCHEMA {
            return PublicVerdict::UNVERIFIABLE {
                missing: "tlbundle schema".to_string(),
            };
        }
    }
    if let Err(error) = monotonicity_check_tlcert(cert, bundle) {
        return verdict_from_error(error, lbl!("monotonicity_check"));
    }
    let bundle = match bundle {
        Some(bundle) => bundle,
        None => {
            return PublicVerdict::UNVERIFIABLE {
                missing: "tlbundle".to_string(),
            }
        }
    };
    if let Some(bundle_ref) = cert.bundle_ref {
        if bundle_ref != bundle.bundle_digest {
            return verdict_from_error(PublicVerifyError::DigestMismatch, lbl!("bundle_ref"));
        }
    }
    if let Err(error) = recompute_digest_tlcert(cert, bundle) {
        return verdict_from_error(error, lbl!("recompute_digest"));
    }
    if let Err(error) = replay_check_tlcert(cert, bundle) {
        return verdict_from_error(error, lbl!("replay_check"));
    }
    if let Err(error) = cohort_check_tlcert(cert, bundle) {
        return verdict_from_error(error, lbl!("cohort_check"));
    }
    PublicVerdict::VALID(cert.status)
}

pub fn verify_bytes(cert_bytes: &[u8], bundle_bytes: Option<&[u8]>) -> PublicVerdict {
    let cert = match decode_tlcert(cert_bytes) {
        Ok(cert) => cert,
        Err(_) => {
            return PublicVerdict::UNVERIFIABLE {
                missing: "tlcert decode".to_string(),
            }
        }
    };
    let bundle = match bundle_bytes {
        Some(bytes) => match decode_tlbundle(bytes) {
            Ok(bundle) => Some(bundle),
            Err(_) => {
                return PublicVerdict::UNVERIFIABLE {
                    missing: "tlbundle decode".to_string(),
                }
            }
        },
        None => None,
    };
    verify(&cert, bundle.as_ref())
}

pub fn verify_interval_membership(cert: &TLCert, proof: &IntervalInclusionProof) -> PublicVerdict {
    match verify_inclusion_proof(&cert.interval_ref, proof) {
        Ok(()) => PublicVerdict::VALID(cert.status),
        Err(_) => verdict_from_error(PublicVerifyError::DigestMismatch, lbl!("interval_membership")),
    }
}

pub fn recompute_digest_tlcert(cert: &TLCert, bundle: &TLBundle) -> Result<(), PublicVerifyError> {
    if bundle.interval_ref != cert.interval_ref {
        return Err(PublicVerifyError::DigestMismatch);
    }
    let digest =
        replay_fragment(&bundle.history_fragment).map_err(|_| PublicVerifyError::MissingData)?;
    if Digest::from(digest) == cert.local_digest {
        Ok(())
    } else {
        Err(PublicVerifyError::DigestMismatch)
    }
}

pub fn replay_check_tlcert(cert: &TLCert, bundle: &TLBundle) -> Result<(), PublicVerifyError> {
    let exec = ShadowExec {
        mode: ShadowMode::PS,
    };
    let result =
        run_shadow(&exec, &bundle.history_fragment).map_err(|_| PublicVerifyError::MissingData)?;
    if Digest::from(result.shadow_digest.0) == cert.shadow_digest {
        Ok(())
    } else {
        Err(PublicVerifyError::ReplayMismatch)
    }
}

pub fn cohort_check_tlcert(cert: &TLCert, bundle: &TLBundle) -> Result<(), PublicVerifyError> {
    if cert.peers.len() != cert.ring_indices.len()
        || cert.peers.len() != cert.peer_new_digests.len()
        || cert.peers.len() < 2
    {
        return Err(PublicVerifyError::CohortMismatch);
    }
    if bundle.cohort_witness.peers != cert.peers
        || bundle.cohort_witness.ring_indices != cert.ring_indices
        || bundle.cohort_witness.peer_new_digests != cert.peer_new_digests
    {
        return Err(PublicVerifyError::CohortMismatch);
    }
    let _cohort_digest = cert_cohort_digest(cert);
    if tlcert_integrity_stamp(cert) != cert.integrity_stamp {
        return Err(PublicVerifyError::CohortMismatch);
    }
    Ok(())
}

pub fn monotonicity_check_tlcert(
    cert: &TLCert,
    bundle: Option<&TLBundle>,
) -> Result<(), PublicVerifyError> {
    match cert.status {
        ReceiptStatus::FINAL => {
            if bundle.is_none() || cert.peers.len() < 2 {
                Err(PublicVerifyError::MissingData)
            } else {
                Ok(())
            }
        }
        ReceiptStatus::SHADOWED => {
            if cert.shadow_digest == Digest::default() {
                Err(PublicVerifyError::MissingData)
            } else {
                Ok(())
            }
        }
        ReceiptStatus::LOCAL => Ok(()),
    }
}

fn verdict_from_error(error: PublicVerifyError, location: &str) -> PublicVerdict {
    match error {
        PublicVerifyError::MissingData => PublicVerdict::UNVERIFIABLE {
            missing: location.to_string(),
        },
        PublicVerifyError::DigestMismatch
        | PublicVerifyError::ReplayMismatch
        | PublicVerifyError::CohortMismatch
        | PublicVerifyError::StatusMismatch => PublicVerdict::DIVERGENT {
            #[cfg(not(feature = "public"))]
            reason: format!("{:?}", error),
            #[cfg(feature = "public")]
            reason: String::new(),
            location: location.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_finality::TLCert;

    #[test]
    fn verify_bytes_rejects_invalid_cert_bytes() {
        assert!(matches!(
            verify_bytes(b"bad", None),
            PublicVerdict::UNVERIFIABLE { .. }
        ));
    }

    #[test]
    fn monotonicity_rejects_final_without_bundle() {
        let cert = TLCert {
            schema: TLCERT_SCHEMA.to_string(),
            status: ReceiptStatus::FINAL,
            interval_ref: Digest([1; 32]),
            local_digest: Digest([1; 32]),
            shadow_digest: Digest([1; 32]),
            replay_params: Default::default(),
            cohort_id: Default::default(),
            peers: vec![Default::default(), Default::default()],
            ring_indices: vec![1, 1],
            peer_new_digests: vec![Digest([2; 32]), Digest([3; 32])],
            integrity_stamp: Digest([0; 32]),
            issued_at_pos: 1,
            bundle_ref: None,
        };
        assert_eq!(
            monotonicity_check_tlcert(&cert, None),
            Err(PublicVerifyError::MissingData)
        );
    }

    #[test]
    fn invalid_input_verdict_is_deterministic() {
        assert_eq!(verify_bytes(b"bad", None), verify_bytes(b"bad", None));
    }
}
