use tl_canon_types::{CohortId, DigestRef, IntervalId, ReceiptId};
use tl_cohort::CohortProof;
use tl_shadow::ShadowDigest;

#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ReceiptStatus {
    LOCAL,
    SHADOWED,
    FINAL,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RwReceipt {
    pub receipt_id: ReceiptId,
    pub status: ReceiptStatus,
    pub local_digest: DigestRef,
    pub shadow_digest: Option<DigestRef>,
    pub proof_of_contact: Option<ProofOfContact>,
    pub time_proof: Option<TimeProof>,
    pub notary: Option<NotaryOfExecution>,
    pub cohort_proof: Option<CohortProof>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofOfContact {
    pub cohort_id: CohortId,
    pub interval_id: IntervalId,
    pub proof_digest: DigestRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeProof {
    pub status: ReceiptStatus,
    pub digest: DigestRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotaryOfExecution {
    pub replay_digest: DigestRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReceiptError {
    StatusRollback,
    ShadowDigestMismatch,
    MissingCohortProof,
    ContentChanged,
}

impl RwReceipt {
    pub fn local(receipt_id: ReceiptId, local_digest: DigestRef) -> Self {
        Self {
            receipt_id,
            status: ReceiptStatus::LOCAL,
            local_digest,
            shadow_digest: None,
            proof_of_contact: None,
            time_proof: Some(TimeProof {
                status: ReceiptStatus::LOCAL,
                digest: local_digest,
            }),
            notary: None,
            cohort_proof: None,
        }
    }
}

pub fn promote_to_shadowed(
    receipt: &mut RwReceipt,
    shadow_digest: ShadowDigest,
) -> Result<(), ReceiptError> {
    if !monotonic_status_check(receipt.status, ReceiptStatus::SHADOWED) {
        return Err(ReceiptError::StatusRollback);
    }
    if receipt.status == ReceiptStatus::SHADOWED && receipt.shadow_digest == Some(shadow_digest.0) {
        return Ok(());
    }
    if receipt.local_digest != shadow_digest.0 {
        return Err(ReceiptError::ShadowDigestMismatch);
    }
    receipt.shadow_digest = Some(shadow_digest.0);
    receipt.notary = Some(NotaryOfExecution {
        replay_digest: shadow_digest.0,
    });
    receipt.time_proof = Some(TimeProof {
        status: ReceiptStatus::SHADOWED,
        digest: shadow_digest.0,
    });
    receipt.status = ReceiptStatus::SHADOWED;
    Ok(())
}

pub fn promote_to_final(
    receipt: &mut RwReceipt,
    cohort_proof: CohortProof,
) -> Result<(), ReceiptError> {
    if !monotonic_status_check(receipt.status, ReceiptStatus::FINAL) {
        return Err(ReceiptError::StatusRollback);
    }
    let shadow_digest = receipt
        .shadow_digest
        .ok_or(ReceiptError::ShadowDigestMismatch)?;
    if shadow_digest != receipt.local_digest {
        return Err(ReceiptError::ShadowDigestMismatch);
    }
    if receipt.status == ReceiptStatus::FINAL {
        if receipt.cohort_proof.as_ref() == Some(&cohort_proof) {
            return Ok(());
        }
        return Err(ReceiptError::ContentChanged);
    }
    receipt.proof_of_contact = Some(ProofOfContact {
        cohort_id: cohort_proof.cohort_id.clone(),
        interval_id: cohort_proof.interval_id,
        proof_digest: cohort_proof.proof_digest,
    });
    receipt.time_proof = Some(TimeProof {
        status: ReceiptStatus::FINAL,
        digest: cohort_proof.proof_digest,
    });
    receipt.cohort_proof = Some(cohort_proof);
    receipt.status = ReceiptStatus::FINAL;
    Ok(())
}

pub fn monotonic_status_check(current: ReceiptStatus, next: ReceiptStatus) -> bool {
    next >= current
}

pub fn monotonic_receipt_update(current: &RwReceipt, next: &RwReceipt) -> Result<(), ReceiptError> {
    if next.status < current.status {
        return Err(ReceiptError::StatusRollback);
    }
    if next.status == current.status && next != current {
        return Err(ReceiptError::ContentChanged);
    }
    if next.status == ReceiptStatus::FINAL && next.cohort_proof.is_none() {
        return Err(ReceiptError::MissingCohortProof);
    }
    if next.status >= ReceiptStatus::SHADOWED && next.shadow_digest != Some(next.local_digest) {
        return Err(ReceiptError::ShadowDigestMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_canon_types::{CohortId, DigestRef, IntervalId, ReceiptId};

    fn proof() -> CohortProof {
        CohortProof {
            cohort_id: CohortId("c".to_string()),
            interval_id: IntervalId(1),
            member_ids: Vec::new(),
            witness_digests: Vec::new(),
            ring_indices: Vec::new(),
            peer_new_digests: Vec::new(),
            threshold: tl_cohort::QuorumThreshold(1),
            proof_digest: DigestRef([1; 32]),
        }
    }

    #[test]
    fn receipt_promotes_monotonically() {
        let mut receipt = RwReceipt::local(ReceiptId(1), DigestRef([2; 32]));
        promote_to_shadowed(&mut receipt, tl_shadow::ShadowDigest(DigestRef([2; 32]))).unwrap();
        promote_to_final(&mut receipt, proof()).unwrap();
        assert_eq!(receipt.status, ReceiptStatus::FINAL);
    }

    #[test]
    fn shadow_mismatch_is_rejected() {
        let mut receipt = RwReceipt::local(ReceiptId(1), DigestRef([2; 32]));
        assert_eq!(
            promote_to_shadowed(&mut receipt, tl_shadow::ShadowDigest(DigestRef([3; 32]))),
            Err(ReceiptError::ShadowDigestMismatch)
        );
    }

    #[test]
    fn rollback_is_rejected() {
        assert!(!monotonic_status_check(
            ReceiptStatus::FINAL,
            ReceiptStatus::LOCAL
        ));
    }
}
