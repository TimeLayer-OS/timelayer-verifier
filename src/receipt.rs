//! The Phase-1 signed receipt envelope: the cohort core fields plus the list of
//! node signatures over the root. This is the serialized authenticity layer the
//! verifier reads and checks against the roster.

use crate::proof::{verify_cohort, CohortSig, CohortVerdict, QuorumMode};
use crate::roster::Roster;
use crate::{field, read_field, CoreFields};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedReceipt {
    pub core: CoreFields,
    pub cohort_proof: Vec<CohortSig>,
}

impl SignedReceipt {
    pub fn root(&self) -> [u8; 32] {
        self.core.root()
    }

    /// Verify the receipt's quorum against a roster (spec §7 signature part).
    pub fn verify(&self, roster: &Roster, k: usize, mode: QuorumMode) -> CohortVerdict {
        verify_cohort(&self.core, &self.cohort_proof, roster, k, mode)
    }

    /// Canonical length-prefixed encoding (file/wire form).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        field(&mut b, "core", &self.core.canonical_bytes());
        field(&mut b, "sig_count", &(self.cohort_proof.len() as u64).to_be_bytes());
        for s in &self.cohort_proof {
            field(&mut b, "node_id", s.node_id.as_bytes());
            field(&mut b, "alg", &[s.alg]);
            field(&mut b, "sig", &s.sig);
        }
        b
    }

    pub fn decode(b: &[u8]) -> Option<SignedReceipt> {
        let mut pos = 0usize;
        let core = CoreFields::decode(read_field(b, &mut pos, "core")?)?;
        let count_b = read_field(b, &mut pos, "sig_count")?;
        let count = u64::from_be_bytes(count_b.try_into().ok()?) as usize;
        let mut cohort_proof = Vec::with_capacity(count.min(4096));
        for _ in 0..count {
            let node_id = String::from_utf8(read_field(b, &mut pos, "node_id")?.to_vec()).ok()?;
            let alg_b = read_field(b, &mut pos, "alg")?;
            if alg_b.len() != 1 {
                return None;
            }
            let sig_b = read_field(b, &mut pos, "sig")?;
            if sig_b.len() != 64 {
                return None;
            }
            let mut sig = [0u8; 64];
            sig.copy_from_slice(sig_b);
            cohort_proof.push(CohortSig {
                node_id,
                alg: alg_b[0],
                sig,
            });
        }
        if pos != b.len() {
            return None;
        }
        Some(SignedReceipt { core, cohort_proof })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::roster::{NodeStatus, Roster, RosterEntry};
    use crate::{keygen, sign_root, IntervalInputs, core_fields_from_interval, ALG_ED25519};

    fn build() -> (SignedReceipt, Roster) {
        let peers = vec!["tl-0".to_string(), "tl-1".to_string(), "tl-2".to_string()];
        // network of 3 nodes
        let mut seeds = Vec::new();
        let mut entries = Vec::new();
        for i in 0..3 {
            let (s, pk) = keygen().unwrap();
            seeds.push(s);
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
        let roster = Roster { epoch: 1, entries };
        let core = core_fields_from_interval(&IntervalInputs {
            interval_ref: [5; 32],
            prev_interval_ref: [0; 32],
            cohort_id: "trial10",
            issued_at_pos: 7,
            issuer_node_id: "tl-0",
            nonce: [9; 16],
            roster_epoch: 1,
            local_digest: [2; 32],
            shadow_digest: [3; 32],
            replay_params: b"rp",
            peers: &peers,
            ring_indices: &[0, 1, 2],
            peer_new_digests: &[[1; 32], [2; 32], [3; 32]],
        });
        let root = core.root();
        let cohort_proof = (0..3)
            .map(|i| CohortSig {
                node_id: format!("tl-{}", i),
                alg: ALG_ED25519,
                sig: sign_root(&seeds[i], &root),
            })
            .collect();
        (SignedReceipt { core, cohort_proof }, roster)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (r, _roster) = build();
        let bytes = r.encode();
        let back = SignedReceipt::decode(&bytes).unwrap();
        assert_eq!(r, back);
        assert_eq!(r.root(), back.root());
    }

    #[test]
    fn decoded_receipt_verifies_and_tamper_fails() {
        let (r, roster) = build();
        let bytes = r.encode();
        let back = SignedReceipt::decode(&bytes).unwrap();
        assert!(back.verify(&roster, 3, QuorumMode::ByNode).valid);

        // flip one byte inside the encoded content -> decode still ok or not, but a
        // verify on the mutated receipt must fail. Mutate a core byte region.
        let mut bad = bytes.clone();
        // find the doc_digest value (after the "core" wrapper + "doc_digest" field)
        let p = bad.windows(10).position(|w| w == b"doc_digest").unwrap();
        bad[p + 10 + 4] ^= 1; // first byte of doc_digest value
        if let Some(b2) = SignedReceipt::decode(&bad) {
            assert!(!b2.verify(&roster, 3, QuorumMode::ByNode).valid);
        }
    }

    #[test]
    fn truncated_bytes_decode_to_none() {
        let (r, _roster) = build();
        let bytes = r.encode();
        assert!(SignedReceipt::decode(&bytes[..bytes.len() - 1]).is_none());
    }
}
