use tl_canon_types::{
    canonical_entry, canonical_payload, CanonBytes, CanonError, CanonReader, CanonWriter,
    CertificateId, CohortId, DigestRef, IntervalId, NodeId, Tick,
};
use tl_cohort::{cohort_proof_digest, CohortProof};
use tl_digest::{digest_bytes, integrity_stamp, interval_digest, Digest};
use tl_receipts::{promote_to_final, ReceiptError, ReceiptStatus, RwReceipt};
use tl_rw_core::{decode_history_fragment, encode_history_fragment, HistoryFragment, RwCoreError};

pub const TLCERT_SCHEMA: &str = "tlcert/1";
pub const TLBUNDLE_SCHEMA: &str = "tlbundle/1";
const MAX_COHORT_VECTOR_ITEMS: u64 = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalFact {
    pub local_digest: DigestRef,
    pub shadow_digest: DigestRef,
    pub proof_of_replay: DigestRef,
    pub cohort_proof: CohortProof,
    pub integrity_stamp: Digest,
    pub issued_at_pos: u64,
    pub replay_params: CanonBytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemporalCertificate {
    pub certificate_id: CertificateId,
    pub status: ReceiptStatus,
    pub interval: FinalizationInterval,
    pub final_fact: FinalFact,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizationInterval {
    pub interval_id: IntervalId,
    pub start: Tick,
    pub end: Tick,
    pub interval_ref: Digest,
    pub history_fragment: HistoryFragment,
    pub replay_params: CanonBytes,
    pub cohort_witness: CohortWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortWitness {
    pub peers: Vec<NodeId>,
    pub ring_indices: Vec<u64>,
    pub peer_new_digests: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityClient {
    pub config: FinalityConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalityConfig {
    pub interval: FinalizationInterval,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TLCert {
    pub schema: String,
    pub status: ReceiptStatus,
    pub interval_ref: Digest,
    pub local_digest: Digest,
    pub shadow_digest: Digest,
    pub replay_params: CanonBytes,
    pub cohort_id: CohortId,
    pub peers: Vec<NodeId>,
    pub ring_indices: Vec<u64>,
    pub peer_new_digests: Vec<Digest>,
    pub integrity_stamp: Digest,
    pub issued_at_pos: u64,
    pub bundle_ref: Option<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TLBundle {
    pub schema: String,
    pub interval_ref: Digest,
    pub history_fragment: HistoryFragment,
    pub replay_params: CanonBytes,
    pub cohort_witness: CohortWitness,
    pub bundle_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalReceiptMember {
    pub index: u64,
    pub local_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalCommitment {
    pub interval_ref: Digest,
    pub receipt_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalInclusionProof {
    pub index: u64,
    pub local_digest: Digest,
    pub ordered_local_digests: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedInterval {
    pub interval_id: IntervalId,
    pub commitment: IntervalCommitment,
    pub certificate: TLCert,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntervalAccumulator {
    pub max_receipts: usize,
    pub max_wait_ticks: u64,
    pub wait_ticks: u64,
    pub members: Vec<IntervalReceiptMember>,
}

impl IntervalAccumulator {
    pub fn new(max_receipts: usize, max_wait_ticks: u64) -> Self {
        Self {
            max_receipts,
            max_wait_ticks,
            wait_ticks: 0,
            members: Vec::new(),
        }
    }

    pub fn push(&mut self, local_digest: Digest) {
        let index = self.members.len() as u64;
        self.members.push(IntervalReceiptMember {
            index,
            local_digest,
        });
    }

    pub fn tick_wait(&mut self) {
        self.wait_ticks = self.wait_ticks.saturating_add(1);
    }

    pub fn should_close(&self) -> bool {
        (!self.members.is_empty() && self.members.len() >= self.max_receipts)
            || (!self.members.is_empty() && self.wait_ticks >= self.max_wait_ticks)
    }

    pub fn commitment(&self) -> IntervalCommitment {
        let digests: Vec<Digest> = self
            .members
            .iter()
            .map(|member| member.local_digest)
            .collect();
        IntervalCommitment {
            interval_ref: interval_ref_from_digests(&digests),
            receipt_count: self.members.len() as u64,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FinalityError {
    Receipt(ReceiptError),
    MissingShadowDigest,
    Canon(CanonError),
    Rw(RwCoreError),
    SchemaMismatch,
    DigestMismatch,
    InvalidStatus,
}

impl From<CanonError> for FinalityError {
    fn from(value: CanonError) -> Self {
        Self::Canon(value)
    }
}

impl From<RwCoreError> for FinalityError {
    fn from(value: RwCoreError) -> Self {
        Self::Rw(value)
    }
}

pub fn finalize(
    receipt: &mut RwReceipt,
    interval: FinalizationInterval,
    cohort_proof: CohortProof,
) -> Result<FinalFact, FinalityError> {
    let shadow_digest = receipt
        .shadow_digest
        .ok_or(FinalityError::MissingShadowDigest)?;
    let stamp = integrity_stamp(
        &receipt.local_digest,
        &shadow_digest,
        &cohort_proof.proof_digest,
    )
    .as_digest();
    let fact = FinalFact {
        local_digest: receipt.local_digest,
        shadow_digest,
        proof_of_replay: shadow_digest,
        cohort_proof: cohort_proof.clone(),
        integrity_stamp: stamp,
        issued_at_pos: interval.end.0,
        replay_params: interval.replay_params.clone(),
    };
    promote_to_final(receipt, cohort_proof).map_err(FinalityError::Receipt)?;
    Ok(fact)
}

pub fn build_certificate(fact: FinalFact, interval: FinalizationInterval) -> TemporalCertificate {
    TemporalCertificate {
        certificate_id: CertificateId(interval.interval_id.0),
        status: ReceiptStatus::FINAL,
        interval,
        final_fact: fact,
    }
}

pub fn certificate_status(certificate: &TemporalCertificate) -> ReceiptStatus {
    certificate.status
}

pub fn export_certificate(fact: FinalFact) -> TLCert {
    let mut cert = TLCert {
        schema: TLCERT_SCHEMA.to_string(),
        status: ReceiptStatus::FINAL,
        interval_ref: Digest::from(fact.local_digest),
        local_digest: Digest::from(fact.local_digest),
        shadow_digest: Digest::from(fact.shadow_digest),
        replay_params: fact.replay_params.clone(),
        cohort_id: fact.cohort_proof.cohort_id.clone(),
        peers: fact.cohort_proof.member_ids.clone(),
        ring_indices: fact.cohort_proof.ring_indices.clone(),
        peer_new_digests: fact.cohort_proof.peer_new_digests.clone(),
        integrity_stamp: fact.integrity_stamp,
        issued_at_pos: fact.issued_at_pos,
        bundle_ref: None,
    };
    cert.integrity_stamp = tlcert_integrity_stamp(&cert);
    cert
}

pub fn export_bundle(interval: FinalizationInterval) -> TLBundle {
    let mut bundle = TLBundle {
        schema: TLBUNDLE_SCHEMA.to_string(),
        interval_ref: interval.interval_ref,
        history_fragment: interval.history_fragment,
        replay_params: interval.replay_params,
        cohort_witness: interval.cohort_witness,
        bundle_digest: Digest::default(),
    };
    bundle.bundle_digest = digest_bytes(tlbundle_body_bytes(&bundle).as_slice());
    bundle
}

pub fn interval_history_fragment(local_digests: &[Digest]) -> HistoryFragment {
    let entries = local_digests
        .iter()
        .enumerate()
        .map(|(idx, digest)| {
            canonical_entry(
                Tick((idx as u64).saturating_add(1)),
                canonical_payload("interval-member", digest.0.to_vec()),
                None,
            )
        })
        .collect();
    HistoryFragment { entries }
}

pub fn interval_ref_from_digests(local_digests: &[Digest]) -> Digest {
    interval_digest(&interval_history_fragment(local_digests).entries)
}

pub fn build_inclusion_proof(
    local_digests: &[Digest],
    index: u64,
) -> Result<IntervalInclusionProof, FinalityError> {
    let local_digest = local_digests
        .get(index as usize)
        .copied()
        .ok_or(FinalityError::DigestMismatch)?;
    Ok(IntervalInclusionProof {
        index,
        local_digest,
        ordered_local_digests: local_digests.to_vec(),
    })
}

pub fn verify_inclusion_proof(
    interval_ref: &Digest,
    proof: &IntervalInclusionProof,
) -> Result<(), FinalityError> {
    let Some(local_digest) = proof.ordered_local_digests.get(proof.index as usize) else {
        return Err(FinalityError::DigestMismatch);
    };
    if local_digest != &proof.local_digest {
        return Err(FinalityError::DigestMismatch);
    }
    if interval_ref_from_digests(&proof.ordered_local_digests) != *interval_ref {
        return Err(FinalityError::DigestMismatch);
    }
    Ok(())
}

pub fn encode_tlcert(cert: &TLCert) -> Vec<u8> {
    let mut writer = CanonWriter::new();
    writer.push_str(&cert.schema);
    writer.push_u8(status_to_u8(cert.status));
    push_digest(&mut writer, &cert.interval_ref);
    push_digest(&mut writer, &cert.local_digest);
    push_digest(&mut writer, &cert.shadow_digest);
    writer.push_bytes(cert.replay_params.as_slice());
    writer.push_str(&cert.cohort_id.0);
    push_node_vec(&mut writer, &cert.peers);
    push_u64_vec(&mut writer, &cert.ring_indices);
    push_digest_vec(&mut writer, &cert.peer_new_digests);
    push_digest(&mut writer, &cert.integrity_stamp);
    writer.push_u64(cert.issued_at_pos);
    match cert.bundle_ref {
        Some(bundle_ref) => {
            writer.push_u8(1);
            push_digest(&mut writer, &bundle_ref);
        }
        None => writer.push_u8(0),
    }
    writer.finish().0
}

pub fn decode_tlcert(bytes: &[u8]) -> Result<TLCert, FinalityError> {
    let mut reader = CanonReader::new(bytes);
    let schema = reader.read_string()?;
    if schema != TLCERT_SCHEMA {
        return Err(FinalityError::SchemaMismatch);
    }
    let status = u8_to_status(reader.read_u8()?)?;
    let interval_ref = read_digest(&mut reader)?;
    let local_digest = read_digest(&mut reader)?;
    let shadow_digest = read_digest(&mut reader)?;
    let replay_params = CanonBytes(reader.read_bytes()?);
    let cohort_id = CohortId(reader.read_string()?);
    let peers = read_node_vec(&mut reader)?;
    let ring_indices = read_u64_vec(&mut reader)?;
    let peer_new_digests = read_digest_vec(&mut reader)?;
    let integrity_stamp = read_digest(&mut reader)?;
    let issued_at_pos = reader.read_u64()?;
    let bundle_ref = match reader.read_u8()? {
        0 => None,
        1 => Some(read_digest(&mut reader)?),
        _ => return Err(FinalityError::Canon(CanonError::InvalidTag)),
    };
    reader.finish()?;
    Ok(TLCert {
        schema,
        status,
        interval_ref,
        local_digest,
        shadow_digest,
        replay_params,
        cohort_id,
        peers,
        ring_indices,
        peer_new_digests,
        integrity_stamp,
        issued_at_pos,
        bundle_ref,
    })
}

pub fn encode_tlbundle(bundle: &TLBundle) -> Vec<u8> {
    let mut out = tlbundle_body_bytes(bundle).0;
    out.extend_from_slice(&bundle.bundle_digest.0);
    out
}

pub fn decode_tlbundle(bytes: &[u8]) -> Result<TLBundle, FinalityError> {
    if bytes.len() < 32 {
        return Err(FinalityError::DigestMismatch);
    }
    let split = bytes.len() - 32;
    let body = &bytes[..split];
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[split..]);
    let bundle_digest = Digest(digest);
    if digest_bytes(body) != bundle_digest {
        return Err(FinalityError::DigestMismatch);
    }
    let mut reader = CanonReader::new(body);
    let schema = reader.read_string()?;
    if schema != TLBUNDLE_SCHEMA {
        return Err(FinalityError::SchemaMismatch);
    }
    let interval_ref = read_digest(&mut reader)?;
    let fragment_bytes = reader.read_bytes()?;
    let history_fragment = decode_history_fragment(&fragment_bytes)?;
    let replay_params = CanonBytes(reader.read_bytes()?);
    let cohort_witness = CohortWitness {
        peers: read_node_vec(&mut reader)?,
        ring_indices: read_u64_vec(&mut reader)?,
        peer_new_digests: read_digest_vec(&mut reader)?,
    };
    reader.finish()?;
    Ok(TLBundle {
        schema,
        interval_ref,
        history_fragment,
        replay_params,
        cohort_witness,
        bundle_digest,
    })
}

pub fn tlbundle_body_bytes(bundle: &TLBundle) -> CanonBytes {
    let mut writer = CanonWriter::new();
    writer.push_str(&bundle.schema);
    push_digest(&mut writer, &bundle.interval_ref);
    let fragment = encode_history_fragment(&bundle.history_fragment);
    writer.push_bytes(fragment.as_slice());
    writer.push_bytes(bundle.replay_params.as_slice());
    push_node_vec(&mut writer, &bundle.cohort_witness.peers);
    push_u64_vec(&mut writer, &bundle.cohort_witness.ring_indices);
    push_digest_vec(&mut writer, &bundle.cohort_witness.peer_new_digests);
    writer.finish()
}

pub fn tlcert_integrity_body_bytes(cert: &TLCert) -> CanonBytes {
    let mut writer = CanonWriter::new();
    writer.push_str(&cert.schema);
    writer.push_u8(status_to_u8(cert.status));
    push_digest(&mut writer, &cert.interval_ref);
    push_digest(&mut writer, &cert.local_digest);
    push_digest(&mut writer, &cert.shadow_digest);
    writer.push_bytes(cert.replay_params.as_slice());
    writer.push_str(&cert.cohort_id.0);
    push_node_vec(&mut writer, &cert.peers);
    push_u64_vec(&mut writer, &cert.ring_indices);
    push_digest_vec(&mut writer, &cert.peer_new_digests);
    writer.push_u64(cert.issued_at_pos);
    match cert.bundle_ref {
        Some(bundle_ref) => {
            writer.push_u8(1);
            push_digest(&mut writer, &bundle_ref);
        }
        None => writer.push_u8(0),
    }
    writer.finish()
}

pub fn tlcert_integrity_stamp(cert: &TLCert) -> Digest {
    digest_bytes(tlcert_integrity_body_bytes(cert).as_slice())
}

pub fn cert_cohort_digest(cert: &TLCert) -> DigestRef {
    cohort_proof_digest(
        IntervalId(cert.issued_at_pos),
        &cert.interval_ref,
        &cert.peers,
        &cert.ring_indices,
        &cert.peer_new_digests,
    )
}

fn status_to_u8(status: ReceiptStatus) -> u8 {
    match status {
        ReceiptStatus::LOCAL => 0,
        ReceiptStatus::SHADOWED => 1,
        ReceiptStatus::FINAL => 2,
    }
}

fn u8_to_status(value: u8) -> Result<ReceiptStatus, FinalityError> {
    match value {
        0 => Ok(ReceiptStatus::LOCAL),
        1 => Ok(ReceiptStatus::SHADOWED),
        2 => Ok(ReceiptStatus::FINAL),
        _ => Err(FinalityError::InvalidStatus),
    }
}

fn push_digest(writer: &mut CanonWriter, digest: &Digest) {
    writer.push_digest_ref(&digest.as_ref());
}

fn read_digest(reader: &mut CanonReader<'_>) -> Result<Digest, FinalityError> {
    Ok(Digest::from(reader.read_digest_ref()?))
}

fn push_node_vec(writer: &mut CanonWriter, nodes: &[NodeId]) {
    writer.push_u64(nodes.len() as u64);
    for node in nodes {
        writer.push_str(&node.0);
    }
}

fn read_node_vec(reader: &mut CanonReader<'_>) -> Result<Vec<NodeId>, FinalityError> {
    let len = reader.read_u64()?;
    if len > MAX_COHORT_VECTOR_ITEMS {
        return Err(FinalityError::Canon(CanonError::LengthOverflow));
    }
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
        out.push(NodeId(reader.read_string()?));
    }
    Ok(out)
}

fn push_u64_vec(writer: &mut CanonWriter, items: &[u64]) {
    writer.push_u64(items.len() as u64);
    for item in items {
        writer.push_u64(*item);
    }
}

fn read_u64_vec(reader: &mut CanonReader<'_>) -> Result<Vec<u64>, FinalityError> {
    let len = reader.read_u64()?;
    if len > MAX_COHORT_VECTOR_ITEMS {
        return Err(FinalityError::Canon(CanonError::LengthOverflow));
    }
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
        out.push(reader.read_u64()?);
    }
    Ok(out)
}

fn push_digest_vec(writer: &mut CanonWriter, items: &[Digest]) {
    writer.push_u64(items.len() as u64);
    for item in items {
        push_digest(writer, item);
    }
}

fn read_digest_vec(reader: &mut CanonReader<'_>) -> Result<Vec<Digest>, FinalityError> {
    let len = reader.read_u64()?;
    if len > MAX_COHORT_VECTOR_ITEMS {
        return Err(FinalityError::Canon(CanonError::LengthOverflow));
    }
    let mut out = Vec::with_capacity(len as usize);
    for _ in 0..len {
        out.push(read_digest(reader)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_canon_types::{canonical_entry, canonical_payload};

    fn proof() -> CohortProof {
        CohortProof {
            cohort_id: CohortId("c".to_string()),
            interval_id: IntervalId(1),
            member_ids: vec![NodeId("a".to_string()), NodeId("b".to_string())],
            witness_digests: vec![DigestRef([2; 32]), DigestRef([3; 32])],
            ring_indices: vec![1, 1],
            peer_new_digests: vec![Digest([2; 32]), Digest([3; 32])],
            threshold: tl_cohort::QuorumThreshold(2),
            proof_digest: DigestRef([4; 32]),
        }
    }

    fn cert() -> TLCert {
        let fact = FinalFact {
            local_digest: DigestRef([1; 32]),
            shadow_digest: DigestRef([1; 32]),
            proof_of_replay: DigestRef([1; 32]),
            cohort_proof: proof(),
            integrity_stamp: Digest([0; 32]),
            issued_at_pos: 1,
            replay_params: CanonBytes(b"replay".to_vec()),
        };
        let mut cert = export_certificate(fact);
        cert.bundle_ref = Some(Digest([9; 32]));
        cert.integrity_stamp = tlcert_integrity_stamp(&cert);
        cert
    }

    #[test]
    fn cert_encode_decode_roundtrip() {
        let cert = cert();
        assert_eq!(decode_tlcert(&encode_tlcert(&cert)).unwrap(), cert);
    }

    #[test]
    fn cert_integrity_changes_with_status() {
        let mut cert = cert();
        let stamp = cert.integrity_stamp;
        cert.status = ReceiptStatus::LOCAL;
        assert_ne!(tlcert_integrity_stamp(&cert), stamp);
    }

    #[test]
    fn bundle_digest_detects_body_tamper() {
        let interval = FinalizationInterval {
            interval_id: IntervalId(1),
            start: Tick(1),
            end: Tick(1),
            interval_ref: Digest([1; 32]),
            history_fragment: HistoryFragment {
                entries: vec![canonical_entry(
                    Tick(1),
                    canonical_payload("f", b"a".to_vec()),
                    None,
                )],
            },
            replay_params: CanonBytes(b"replay".to_vec()),
            cohort_witness: CohortWitness {
                peers: vec![NodeId("a".to_string()), NodeId("b".to_string())],
                ring_indices: vec![1, 1],
                peer_new_digests: vec![Digest([2; 32]), Digest([3; 32])],
            },
        };
        let mut bytes = encode_tlbundle(&export_bundle(interval));
        bytes[5] ^= 1;
        assert!(decode_tlbundle(&bytes).is_err());
    }
}
