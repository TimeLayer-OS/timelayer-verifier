//! cohortProof (spec §4.1) and the signature-quorum verification (spec §7).
//! This is the heart: the verifier recomputes `root` from content and counts
//! `≥ k` valid signatures from DISTINCT signers (by node or by operator) against
//! the roster active at the receipt's epoch. Closes fabrication-from-scratch.

use crate::roster::Roster;
use crate::{verify_root, CoreFields, ALG_ED25519};

/// One node's signature over `root` (spec §4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortSig {
    pub node_id: String,
    pub alg: u8,
    pub sig: [u8; 64],
}

/// How `k` is counted. Run-in uses ByNode (all keys are ours today); production
/// uses ByOperator with Phase 2 (distinct real operators). Spec §8.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuorumMode {
    ByNode,
    ByOperator,
}

/// Result of the signature-quorum check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CohortVerdict {
    pub valid: bool,
    pub distinct_signers: usize,
    pub k: usize,
}

/// Spec §7 (steps 2,4,5,7) at the signature level: recompute `root` FROM CONTENT,
/// then count valid signatures from distinct signers against the roster.
///
/// `root` is ALWAYS recomputed from `fields` — never taken from the receipt — so a
/// real signature cannot be pasted next to fabricated content.
pub fn verify_cohort(
    fields: &CoreFields,
    proof: &[CohortSig],
    roster: &Roster,
    k: usize,
    mode: QuorumMode,
) -> CohortVerdict {
    let root = fields.root(); // step 2: recompute from content
    let epoch = fields.roster_epoch;
    let mut seen: Vec<String> = Vec::new();
    for s in proof {
        if s.alg != ALG_ED25519 {
            continue;
        }
        let entry = match roster.active_at(&s.node_id, epoch) {
            Some(e) => e,
            None => continue, // missing / revoked / out-of-window
        };
        let id = match mode {
            QuorumMode::ByNode => entry.node_id.clone(),
            QuorumMode::ByOperator => entry.operator.clone(),
        };
        if seen.contains(&id) {
            continue; // only distinct signers count
        }
        if verify_root(&entry.pubkey, &root, &s.sig) {
            seen.push(id);
        }
    }
    CohortVerdict {
        valid: seen.len() >= k,
        distinct_signers: seen.len(),
        k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{keygen, sign_root, roster::{NodeStatus, RosterEntry}};

    fn fields(doc: u8) -> CoreFields {
        CoreFields {
            doc_digest: [doc; 32],
            prev_digest: [0; 32],
            workflow_id: "wf".into(),
            step_index: 1,
            issuer: "tl-0".into(),
            nonce: [4; 16],
            roster_epoch: 1,
            meta_digest: [5; 32],
            ring_digest: [6; 32],
        }
    }

    // n nodes, each its own operator op-i; returns seeds + roster.
    fn network(n: usize) -> (Vec<[u8; 32]>, Roster) {
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
        (seeds, Roster { epoch: 1, entries })
    }

    fn sign_as(seeds: &[[u8; 32]], roster: &Roster, who: &[usize], f: &CoreFields) -> Vec<CohortSig> {
        let root = f.root();
        who.iter()
            .map(|&i| CohortSig {
                node_id: roster.entries[i].node_id.clone(),
                alg: ALG_ED25519,
                sig: sign_root(&seeds[i], &root),
            })
            .collect()
    }

    // Test 1: k valid sigs from k distinct operators -> VALID
    #[test]
    fn t1_quorum_reached_is_valid() {
        let (seeds, roster) = network(11);
        let f = fields(1);
        let proof = sign_as(&seeds, &roster, &[0, 1, 2, 3, 4, 5], &f);
        assert!(verify_cohort(&f, &proof, &roster, 6, QuorumMode::ByOperator).valid);
    }

    // Test 2: any tampered content byte -> root changes -> NOT VALID
    #[test]
    fn t2_tampered_content_is_not_valid() {
        let (seeds, roster) = network(11);
        let f = fields(1);
        let proof = sign_as(&seeds, &roster, &[0, 1, 2, 3, 4, 5], &f);
        let mut tampered = f.clone();
        tampered.step_index = 999; // change one core field
        assert!(!verify_cohort(&tampered, &proof, &roster, 6, QuorumMode::ByOperator).valid);
    }

    // Test 3: k-1 sigs -> NOT VALID
    #[test]
    fn t3_below_threshold_is_not_valid() {
        let (seeds, roster) = network(11);
        let f = fields(1);
        let proof = sign_as(&seeds, &roster, &[0, 1, 2, 3, 4], &f); // 5 < 6
        assert!(!verify_cohort(&f, &proof, &roster, 6, QuorumMode::ByOperator).valid);
    }

    // Test 4: k sigs but < k distinct OPERATORS -> NOT VALID (by_operator);
    // the SAME proof is VALID by_node (the quorum_mode flag in action).
    #[test]
    fn t4_distinct_operators_enforced() {
        let (mut seeds, mut roster) = network(2);
        // add a 3rd node owned by the SAME operator as node 0
        let (seed2, pk2) = keygen().unwrap();
        seeds.push(seed2);
        roster.entries.push(RosterEntry {
            node_id: "tl-2".into(),
            pubkey: pk2,
            alg: ALG_ED25519,
            operator: "op-0".into(), // same operator as tl-0
            region: "EU".into(),
            status: NodeStatus::Active,
            valid_from: 0,
            valid_to: None,
        });
        let f = fields(1);
        // tl-0 and tl-2 => 2 sigs, 2 distinct NODES but only 1 distinct OPERATOR
        let proof = sign_as(&seeds, &roster, &[0, 2], &f);
        assert!(!verify_cohort(&f, &proof, &roster, 2, QuorumMode::ByOperator).valid);
        assert!(verify_cohort(&f, &proof, &roster, 2, QuorumMode::ByNode).valid);
    }

    // Test 5: signature from a revoked / nonexistent node is not counted
    #[test]
    fn t5_revoked_or_unknown_not_counted() {
        let (seeds, mut roster) = network(11);
        let f = fields(1);
        let proof = sign_as(&seeds, &roster, &[0, 1, 2, 3, 4, 5], &f);
        // revoke tl-5 -> only 5 valid -> NOT VALID at k=6
        roster.entries[5].status = NodeStatus::Revoked;
        assert!(!verify_cohort(&f, &proof, &roster, 6, QuorumMode::ByOperator).valid);
        // a sig claiming an unknown node is ignored
        let mut p2 = sign_as(&seeds, &roster, &[0, 1, 2, 3, 4], &f);
        p2.push(CohortSig { node_id: "ghost".into(), alg: ALG_ED25519, sig: [0; 64] });
        assert!(!verify_cohort(&f, &p2, &roster, 6, QuorumMode::ByOperator).valid);
    }

    // Test 6 (THE main one): fabrication from scratch on a machine WITHOUT the
    // nodes' private keys. The attacker has every public key and the full
    // algorithm, builds a receipt for a NEW document, recomputes all hashes/root
    // — but cannot produce k real signatures.
    #[test]
    fn t6_fabrication_from_scratch_is_not_valid() {
        let (_honest_seeds, roster) = network(11);
        // attacker only sees the roster (public keys) + algorithm. New document:
        let forged = fields(0xAA);

        // ---- BEFORE (hash-only world): any party with public inputs reproduces
        // the "proof" hash, so the fabricated receipt passes. This is the hole.
        let before_proof = *blake3::hash(&forged.canonical_bytes()).as_bytes();
        let before_valid = before_proof == *blake3::hash(&forged.canonical_bytes()).as_bytes();
        assert!(before_valid, "hash-only model accepts a fabricated receipt (the hole)");

        // ---- AFTER (signatures): attacker has no private keys. Best it can do is
        // sign with keys IT controls (fresh keypairs not in the roster).
        let mut attacker_proof = Vec::new();
        for i in 0..11 {
            let (atk_seed, _atk_pk) = keygen().unwrap();
            attacker_proof.push(CohortSig {
                node_id: format!("tl-{}", i), // claims a real node...
                alg: ALG_ED25519,
                sig: sign_root(&atk_seed, &forged.root()), // ...but signs with a key not on the roster
            });
        }
        let verdict = verify_cohort(&forged, &attacker_proof, &roster, 6, QuorumMode::ByOperator);
        assert!(!verdict.valid, "signatures: fabrication-from-scratch is NOT VALID");
        assert_eq!(verdict.distinct_signers, 0, "no signature matches a roster key");
    }
}
