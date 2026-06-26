use tl_canon_types::{CohortId, DigestRef, IntervalId, NodeId};
use tl_digest::{digest_bytes, Digest};
use tl_touch::TouchRound;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cohort {
    pub id: CohortId,
    pub members: Vec<CohortMember>,
    pub config: CohortConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortMember {
    pub node_id: NodeId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortConfig {
    pub cohort_size: usize,
    pub quorum_threshold: QuorumThreshold,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QuorumThreshold(pub usize);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MicroHistory {
    pub interval_id: IntervalId,
    pub interval_ref: Digest,
    pub peers: Vec<NodeId>,
    pub ring_indices: Vec<u64>,
    pub peer_new_digests: Vec<Digest>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortProof {
    pub cohort_id: CohortId,
    pub interval_id: IntervalId,
    pub member_ids: Vec<NodeId>,
    pub witness_digests: Vec<DigestRef>,
    pub ring_indices: Vec<u64>,
    pub peer_new_digests: Vec<Digest>,
    pub threshold: QuorumThreshold,
    pub proof_digest: DigestRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortTime {
    pub interval_id: IntervalId,
    pub round: CohortRound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortRound {
    pub round_id: u64,
    pub touch_rounds: Vec<TouchRound>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CohortError {
    QuorumNotReached,
    EmptyCohort,
    InvalidWitness,
}

impl Default for CohortConfig {
    fn default() -> Self {
        trial7_config()
    }
}

pub fn local3_config() -> CohortConfig {
    CohortConfig {
        cohort_size: 3,
        quorum_threshold: QuorumThreshold(2),
    }
}

pub fn trial7_config() -> CohortConfig {
    CohortConfig {
        cohort_size: 4,
        quorum_threshold: QuorumThreshold(3),
    }
}

pub fn cohort_proof_digest(
    interval_id: IntervalId,
    interval_ref: &Digest,
    peers: &[NodeId],
    ring_indices: &[u64],
    peer_new_digests: &[Digest],
) -> DigestRef {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&interval_id.0.to_be_bytes());
    bytes.extend_from_slice(&interval_ref.0);
    bytes.extend_from_slice(&(peers.len() as u64).to_be_bytes());
    for peer in peers {
        bytes.extend_from_slice(&(peer.0.len() as u64).to_be_bytes());
        bytes.extend_from_slice(peer.0.as_bytes());
    }
    bytes.extend_from_slice(&(ring_indices.len() as u64).to_be_bytes());
    for ring_index in ring_indices {
        bytes.extend_from_slice(&ring_index.to_be_bytes());
    }
    bytes.extend_from_slice(&(peer_new_digests.len() as u64).to_be_bytes());
    for digest in peer_new_digests {
        bytes.extend_from_slice(&digest.0);
    }
    digest_bytes(&bytes).as_ref()
}

pub fn build_cohort_proof(
    cohort: &Cohort,
    micro_history: &MicroHistory,
) -> Result<CohortProof, CohortError> {
    if cohort.members.is_empty() {
        return Err(CohortError::EmptyCohort);
    }
    if micro_history.peers.len() != micro_history.ring_indices.len()
        || micro_history.peers.len() != micro_history.peer_new_digests.len()
    {
        return Err(CohortError::InvalidWitness);
    }
    if !quorum_reached(&cohort.config, micro_history.peers.len()) {
        return Err(CohortError::QuorumNotReached);
    }
    let witness_digests: Vec<DigestRef> = micro_history
        .peer_new_digests
        .iter()
        .map(|digest| digest.as_ref())
        .collect();
    let proof_digest = cohort_proof_digest(
        micro_history.interval_id,
        &micro_history.interval_ref,
        &micro_history.peers,
        &micro_history.ring_indices,
        &micro_history.peer_new_digests,
    );
    Ok(CohortProof {
        cohort_id: cohort.id.clone(),
        interval_id: micro_history.interval_id,
        member_ids: micro_history.peers.clone(),
        witness_digests,
        ring_indices: micro_history.ring_indices.clone(),
        peer_new_digests: micro_history.peer_new_digests.clone(),
        threshold: cohort.config.quorum_threshold,
        proof_digest,
    })
}

pub fn quorum_reached(config: &CohortConfig, witness_count: usize) -> bool {
    witness_count >= config.quorum_threshold.0 && witness_count <= config.cohort_size
}

pub fn confirm_interval(
    cohort: &Cohort,
    micro_history: &MicroHistory,
) -> Result<CohortProof, CohortError> {
    build_cohort_proof(cohort, micro_history)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cohort() -> Cohort {
        Cohort {
            id: CohortId("c".to_string()),
            members: vec![
                CohortMember {
                    node_id: NodeId("a".to_string()),
                },
                CohortMember {
                    node_id: NodeId("b".to_string()),
                },
                CohortMember {
                    node_id: NodeId("c".to_string()),
                },
            ],
            config: local3_config(),
        }
    }

    #[test]
    fn proof_builds_when_quorum_reached() {
        let peers = vec![NodeId("a".to_string()), NodeId("b".to_string())];
        let micro = MicroHistory {
            interval_id: IntervalId(1),
            interval_ref: Digest([1; 32]),
            peers,
            ring_indices: vec![1, 1],
            peer_new_digests: vec![Digest([2; 32]), Digest([3; 32])],
        };
        assert!(build_cohort_proof(&cohort(), &micro).is_ok());
    }

    #[test]
    fn proof_fails_without_quorum() {
        let micro = MicroHistory {
            interval_id: IntervalId(1),
            interval_ref: Digest([1; 32]),
            peers: vec![NodeId("a".to_string())],
            ring_indices: vec![1],
            peer_new_digests: vec![Digest([2; 32])],
        };
        assert_eq!(
            build_cohort_proof(&cohort(), &micro),
            Err(CohortError::QuorumNotReached)
        );
    }

    #[test]
    fn proof_digest_is_deterministic() {
        let peers = vec![NodeId("a".to_string()), NodeId("b".to_string())];
        assert_eq!(
            cohort_proof_digest(
                IntervalId(1),
                &Digest([1; 32]),
                &peers,
                &[1, 2],
                &[Digest([3; 32]), Digest([4; 32])]
            ),
            cohort_proof_digest(
                IntervalId(1),
                &Digest([1; 32]),
                &peers,
                &[1, 2],
                &[Digest([3; 32]), Digest([4; 32])]
            )
        );
    }
}
