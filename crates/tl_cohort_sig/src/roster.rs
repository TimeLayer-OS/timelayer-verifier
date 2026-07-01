//! Public roster (spec §4.2, §9): node_id → pubkey → operator → status → epochs.
//! Append-only, versioned by epoch; in Phase 2 the roster digest is anchored on
//! chain. This module holds the in-memory model, a canonical text encoding, and
//! `roster_digest` (what Phase 2 anchors).

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NodeStatus {
    Active,
    Revoked,
}

impl NodeStatus {
    fn as_str(&self) -> &'static str {
        match self {
            NodeStatus::Active => "active",
            NodeStatus::Revoked => "revoked",
        }
    }
    fn parse(s: &str) -> Option<NodeStatus> {
        match s {
            "active" => Some(NodeStatus::Active),
            "revoked" => Some(NodeStatus::Revoked),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RosterEntry {
    pub node_id: String,
    pub pubkey: [u8; 32],
    pub alg: u8,
    pub operator: String,
    pub region: String,
    pub status: NodeStatus,
    pub valid_from: u64,
    pub valid_to: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roster {
    pub epoch: u64,
    pub entries: Vec<RosterEntry>,
}

impl Roster {
    pub fn lookup(&self, node_id: &str) -> Option<&RosterEntry> {
        self.entries.iter().find(|e| e.node_id == node_id)
    }

    /// The entry for `node_id` IF it is active at `epoch` (status active,
    /// valid_from ≤ epoch < valid_to). Spec §7 step 5.
    pub fn active_at(&self, node_id: &str, epoch: u64) -> Option<&RosterEntry> {
        self.lookup(node_id).filter(|e| {
            e.status == NodeStatus::Active
                && e.valid_from <= epoch
                && e.valid_to.map_or(true, |to| epoch < to)
        })
    }

    /// Deterministic digest of the roster at this epoch — what Phase 2 anchors on
    /// chain so the cohort membership cannot be rewritten after the fact.
    pub fn roster_digest(&self) -> [u8; 32] {
        let mut sorted: Vec<&RosterEntry> = self.entries.iter().collect();
        sorted.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        let mut h = blake3::Hasher::new();
        h.update(b"TimeLayer-roster-v1\x00");
        h.update(&self.epoch.to_be_bytes());
        for e in sorted {
            let line = to_line(e);
            h.update(&(line.len() as u64).to_be_bytes());
            h.update(line.as_bytes());
        }
        *h.finalize().as_bytes()
    }
}

use crate::{hex_decode, hex_encode};

/// Canonical one-line encoding (append-only file format).
pub fn to_line(e: &RosterEntry) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}",
        e.node_id,
        hex_encode(&e.pubkey),
        e.alg,
        e.operator,
        e.region,
        e.status.as_str(),
        e.valid_from,
        e.valid_to.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
    )
}

pub fn parse_line(line: &str) -> Option<RosterEntry> {
    let p: Vec<&str> = line.split('|').collect();
    if p.len() != 8 {
        return None;
    }
    let pk = hex_decode(p[1])?;
    if pk.len() != 32 {
        return None;
    }
    let mut pubkey = [0u8; 32];
    pubkey.copy_from_slice(&pk);
    Some(RosterEntry {
        node_id: p[0].to_string(),
        pubkey,
        alg: p[2].parse().ok()?,
        operator: p[3].to_string(),
        region: p[4].to_string(),
        status: NodeStatus::parse(p[5])?,
        valid_from: p[6].parse().ok()?,
        valid_to: if p[7] == "-" { None } else { Some(p[7].parse().ok()?) },
    })
}

/// Parse a roster file: first line `epoch=<n>`, then one entry per line
/// (comments `#` and blanks ignored).
pub fn parse_roster(text: &str) -> Option<Roster> {
    let mut epoch = None;
    let mut entries = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("epoch=") {
            epoch = Some(rest.parse().ok()?);
        } else {
            entries.push(parse_line(line)?);
        }
    }
    Some(Roster {
        epoch: epoch?,
        entries,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(node: &str, op: &str, status: NodeStatus, from: u64, to: Option<u64>) -> RosterEntry {
        RosterEntry {
            node_id: node.to_string(),
            pubkey: [7; 32],
            alg: 1,
            operator: op.to_string(),
            region: "DE".to_string(),
            status,
            valid_from: from,
            valid_to: to,
        }
    }

    #[test]
    fn active_at_respects_status_and_window() {
        let r = Roster {
            epoch: 5,
            entries: vec![
                entry("tl-0", "op-0", NodeStatus::Active, 0, None),
                entry("tl-1", "op-1", NodeStatus::Revoked, 0, None),
                entry("tl-2", "op-2", NodeStatus::Active, 6, None), // not yet valid at 5
                entry("tl-3", "op-3", NodeStatus::Active, 0, Some(4)), // expired before 5
            ],
        };
        assert!(r.active_at("tl-0", 5).is_some());
        assert!(r.active_at("tl-1", 5).is_none(), "revoked");
        assert!(r.active_at("tl-2", 5).is_none(), "not yet valid");
        assert!(r.active_at("tl-3", 5).is_none(), "expired");
        assert!(r.active_at("nope", 5).is_none());
    }

    #[test]
    fn roundtrip_line_and_roster() {
        let r = Roster {
            epoch: 2,
            entries: vec![
                entry("tl-0", "op-0", NodeStatus::Active, 0, None),
                entry("tl-1", "op-1", NodeStatus::Active, 0, Some(9)),
            ],
        };
        let text = format!("epoch={}\n{}\n{}", r.epoch, to_line(&r.entries[0]), to_line(&r.entries[1]));
        let parsed = parse_roster(&text).unwrap();
        assert_eq!(parsed, r);
        // digest is deterministic and order-independent
        let mut shuffled = r.clone();
        shuffled.entries.reverse();
        assert_eq!(r.roster_digest(), shuffled.roster_digest());
    }
}
