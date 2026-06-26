use tl_canon_types::{CanonBytes, CanonEntry, Canonical, DigestRef, IntegrityStampRef, NodeId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Digest(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct IntegrityStamp(pub [u8; 32]);

impl Digest {
    pub fn as_ref(&self) -> DigestRef {
        DigestRef(self.0)
    }
}

impl IntegrityStamp {
    pub fn as_ref(&self) -> IntegrityStampRef {
        IntegrityStampRef(self.0)
    }

    pub fn as_digest(&self) -> Digest {
        Digest(self.0)
    }
}

impl From<Digest> for DigestRef {
    fn from(value: Digest) -> Self {
        value.as_ref()
    }
}

impl From<DigestRef> for Digest {
    fn from(value: DigestRef) -> Self {
        Digest(value.0)
    }
}

impl From<IntegrityStamp> for IntegrityStampRef {
    fn from(value: IntegrityStamp) -> Self {
        value.as_ref()
    }
}

pub fn digest_bytes(bytes: &[u8]) -> Digest {
    Digest(*blake3::hash(bytes).as_bytes())
}

pub fn digest_entry(entry: &CanonEntry) -> Digest {
    digest_bytes(entry.canonical_bytes().as_slice())
}

pub fn digest_pair(left: &DigestRef, right: &DigestRef) -> Digest {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(&left.0);
    bytes.extend_from_slice(&right.0);
    digest_bytes(&bytes)
}

pub fn digest_sequence(items: &[CanonBytes]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    for item in items {
        hasher.update(&(item.as_slice().len() as u64).to_be_bytes());
        hasher.update(item.as_slice());
    }
    Digest(*hasher.finalize().as_bytes())
}

pub fn digest_refs(items: &[Digest]) -> Digest {
    let encoded: Vec<CanonBytes> = items
        .iter()
        .map(|digest| CanonBytes(digest.0.to_vec()))
        .collect();
    digest_sequence(&encoded)
}

pub fn ring_link(previous: &DigestRef, current: &DigestRef) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"ring-link");
    bytes.extend_from_slice(&previous.0);
    bytes.extend_from_slice(&current.0);
    digest_bytes(&bytes)
}

pub fn ring_touch_digest(
    previous: &Digest,
    interval_ref: &Digest,
    peers: &[NodeId],
    ring_index: u64,
) -> Digest {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&previous.0);
    bytes.extend_from_slice(&interval_ref.0);
    bytes.extend_from_slice(&(peers.len() as u64).to_be_bytes());
    for peer in peers {
        bytes.extend_from_slice(&(peer.0.len() as u64).to_be_bytes());
        bytes.extend_from_slice(peer.0.as_bytes());
    }
    bytes.extend_from_slice(&ring_index.to_be_bytes());
    digest_bytes(&bytes)
}

pub fn interval_digest(entries: &[CanonEntry]) -> Digest {
    let bytes: Vec<CanonBytes> = entries.iter().map(Canonical::canonical_bytes).collect();
    digest_sequence(&bytes)
}

pub fn integrity_stamp(
    local_digest: &DigestRef,
    shadow_digest: &DigestRef,
    cohort_digest: &DigestRef,
) -> IntegrityStamp {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"integrity-stamp");
    bytes.extend_from_slice(&local_digest.0);
    bytes.extend_from_slice(&shadow_digest.0);
    bytes.extend_from_slice(&cohort_digest.0);
    IntegrityStamp(digest_bytes(&bytes).0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_canon_types::{canonical_entry, canonical_payload, Tick};

    #[test]
    fn digest_bytes_is_deterministic() {
        assert_eq!(digest_bytes(b"abc"), digest_bytes(b"abc"));
    }

    #[test]
    fn digest_sequence_is_order_sensitive() {
        let a = CanonBytes(b"a".to_vec());
        let b = CanonBytes(b"b".to_vec());
        assert_ne!(
            digest_sequence(&[a.clone(), b.clone()]),
            digest_sequence(&[b, a])
        );
    }

    #[test]
    fn interval_digest_changes_when_entry_changes() {
        let first = canonical_entry(Tick(1), canonical_payload("d", b"a".to_vec()), None);
        let second = canonical_entry(Tick(1), canonical_payload("d", b"b".to_vec()), None);
        assert_ne!(interval_digest(&[first]), interval_digest(&[second]));
    }
}
