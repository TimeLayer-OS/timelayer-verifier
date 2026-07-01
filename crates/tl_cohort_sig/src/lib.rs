//! Phase 1 — cohort signatures (Ed25519) and the canonical `root` they sign.
//!
//! Implements exactly TimeLayer Phase-1 spec §2 (primitives), §3 (canonical
//! serialization + root). The field SOURCES (which interval value becomes which
//! core field) are bridged elsewhere; this crate fixes the byte format and crypto.

pub mod proof;
pub mod receipt;
pub mod roster;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Domain separation for the cohort root (spec §3.3). A signature over this root
/// can never be replayed as a signature in another context.
pub const DOMAIN: &[u8] = b"TimeLayer-cohort-root-v1\x00";

/// Signature algorithm tag (spec §2). Always Ed25519 for now.
pub const ALG_ED25519: u8 = 0x01;

/// Lowercase hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// BLAKE3 hex of bytes — used to store/compare API tokens by hash (never plaintext).
pub fn blake3_hex(bytes: &[u8]) -> String {
    hex_encode(blake3::hash(bytes).as_bytes())
}

/// Decode hex (lower/upper). `None` on odd length or non-hex characters.
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// `field(name, value) = len2(name) || name || len4(value) || value` (spec §3.1).
/// Lengths are big-endian. `name` is ASCII.
pub(crate) fn field(out: &mut Vec<u8>, name: &str, value: &[u8]) {
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
}

/// The fields the cohort root commits to, in the fixed order. Spec §3.2 (8 fields)
/// plus `ring_digest` (field 9) so the signatures also cover the cohort ring
/// structure/order — the notarial transport (locked decision 2026-06-17).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoreFields {
    pub doc_digest: [u8; 32],
    pub prev_digest: [u8; 32],
    pub workflow_id: String,
    pub step_index: u64,
    pub issuer: String,
    pub nonce: [u8; 16],
    pub roster_epoch: u64,
    pub meta_digest: [u8; 32],
    /// BLAKE3 over the canonical cohort ring witness (peers, ring_indices,
    /// peer_new_digests). Binds the ring into the signed root.
    pub ring_digest: [u8; 32],
}

impl CoreFields {
    /// Byte-identical canonical serialization (spec §3.2). Every node and the
    /// verifier MUST produce exactly these bytes.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut b = Vec::new();
        field(&mut b, "doc_digest", &self.doc_digest);
        field(&mut b, "prev_digest", &self.prev_digest);
        field(&mut b, "workflow_id", self.workflow_id.as_bytes());
        field(&mut b, "step_index", &self.step_index.to_be_bytes());
        field(&mut b, "issuer", self.issuer.as_bytes());
        field(&mut b, "nonce", &self.nonce);
        field(&mut b, "roster_epoch", &self.roster_epoch.to_be_bytes());
        field(&mut b, "meta_digest", &self.meta_digest);
        field(&mut b, "ring_digest", &self.ring_digest);
        b
    }

    /// `root = BLAKE3(DOMAIN || canonical_bytes)` (spec §3.3). 32 bytes. This is
    /// what cohort nodes sign and what the verifier recomputes from content.
    pub fn root(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(DOMAIN);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }

    /// Inverse of `canonical_bytes`: parse the 9 fields back (validating names and
    /// fixed sizes). `None` on any malformed/short/misnamed input.
    pub fn decode(bytes: &[u8]) -> Option<CoreFields> {
        let mut pos = 0usize;
        let doc_digest = read_array::<32>(bytes, &mut pos, "doc_digest")?;
        let prev_digest = read_array::<32>(bytes, &mut pos, "prev_digest")?;
        let workflow_id = String::from_utf8(read_field(bytes, &mut pos, "workflow_id")?.to_vec()).ok()?;
        let step_index = u64::from_be_bytes(read_array::<8>(bytes, &mut pos, "step_index")?);
        let issuer = String::from_utf8(read_field(bytes, &mut pos, "issuer")?.to_vec()).ok()?;
        let nonce = read_array::<16>(bytes, &mut pos, "nonce")?;
        let roster_epoch = u64::from_be_bytes(read_array::<8>(bytes, &mut pos, "roster_epoch")?);
        let meta_digest = read_array::<32>(bytes, &mut pos, "meta_digest")?;
        let ring_digest = read_array::<32>(bytes, &mut pos, "ring_digest")?;
        if pos != bytes.len() {
            return None; // trailing garbage
        }
        Some(CoreFields {
            doc_digest,
            prev_digest,
            workflow_id,
            step_index,
            issuer,
            nonce,
            roster_epoch,
            meta_digest,
            ring_digest,
        })
    }
}

/// Read one `field(name, value)` and return the value slice (name must match).
pub(crate) fn read_field<'a>(b: &'a [u8], pos: &mut usize, name: &str) -> Option<&'a [u8]> {
    if *pos + 2 > b.len() {
        return None;
    }
    let nlen = u16::from_be_bytes([b[*pos], b[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + nlen > b.len() || &b[*pos..*pos + nlen] != name.as_bytes() {
        return None;
    }
    *pos += nlen;
    if *pos + 4 > b.len() {
        return None;
    }
    let vlen = u32::from_be_bytes([b[*pos], b[*pos + 1], b[*pos + 2], b[*pos + 3]]) as usize;
    *pos += 4;
    if *pos + vlen > b.len() {
        return None;
    }
    let v = &b[*pos..*pos + vlen];
    *pos += vlen;
    Some(v)
}

fn read_array<const N: usize>(b: &[u8], pos: &mut usize, name: &str) -> Option<[u8; N]> {
    let v = read_field(b, pos, name)?;
    if v.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(v);
    Some(out)
}

// ---- Derived digests for the bridge (map §3.2) -----------------------------
// These MUST be computed identically by every honest node and by the verifier.

/// `meta_digest` = BLAKE3 over the (deterministic, agreed) replay/shadow proof:
/// local_digest, shadow_digest, replay_params. Length-prefixed + domain-separated.
pub fn meta_digest(local: &[u8; 32], shadow: &[u8; 32], replay_params: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"TimeLayer-meta-v1\x00");
    h.update(local);
    h.update(shadow);
    h.update(&(replay_params.len() as u64).to_be_bytes());
    h.update(replay_params);
    *h.finalize().as_bytes()
}

/// `ring_digest` = BLAKE3 over the canonical cohort ring witness in the given
/// order (peers, ring_indices, peer_new_digests). Binds the ring into the root.
pub fn ring_digest(
    peers: &[String],
    ring_indices: &[u64],
    peer_new_digests: &[[u8; 32]],
) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"TimeLayer-ring-v1\x00");
    h.update(&(peers.len() as u64).to_be_bytes());
    for p in peers {
        h.update(&(p.len() as u64).to_be_bytes());
        h.update(p.as_bytes());
    }
    h.update(&(ring_indices.len() as u64).to_be_bytes());
    for r in ring_indices {
        h.update(&r.to_be_bytes());
    }
    h.update(&(peer_new_digests.len() as u64).to_be_bytes());
    for d in peer_new_digests {
        h.update(d);
    }
    *h.finalize().as_bytes()
}

// ---- Bridge: interval -> CoreFields (locked map 2026-06-17) ----------------

/// The interval values the initiator gathers to build a cohort root. Maps 1:1 to
/// `CoreFields` via the locked field map.
pub struct IntervalInputs<'a> {
    pub interval_ref: [u8; 32],      // -> doc_digest (content identity)
    pub prev_interval_ref: [u8; 32], // -> prev_digest (0x32 zeros if first)
    pub cohort_id: &'a str,          // -> workflow_id
    pub issued_at_pos: u64,          // -> step_index
    pub issuer_node_id: &'a str,     // -> issuer (the INITIATOR)
    pub nonce: [u8; 16],             // -> nonce (initiator generates once)
    pub roster_epoch: u64,           // -> roster_epoch
    pub local_digest: [u8; 32],      // \
    pub shadow_digest: [u8; 32],     //  > -> meta_digest
    pub replay_params: &'a [u8],     // /
    pub peers: &'a [String],         // \
    pub ring_indices: &'a [u64],     //  > -> ring_digest
    pub peer_new_digests: &'a [[u8; 32]], // /
}

/// Assemble the 9 cohort core fields from one interval (locked map). Every honest
/// node and the verifier build the same `CoreFields` and therefore the same root.
pub fn core_fields_from_interval(i: &IntervalInputs) -> CoreFields {
    CoreFields {
        doc_digest: i.interval_ref,
        prev_digest: i.prev_interval_ref,
        workflow_id: i.cohort_id.to_string(),
        step_index: i.issued_at_pos,
        issuer: i.issuer_node_id.to_string(),
        nonce: i.nonce,
        roster_epoch: i.roster_epoch,
        meta_digest: meta_digest(&i.local_digest, &i.shadow_digest, i.replay_params),
        ring_digest: ring_digest(i.peers, i.ring_indices, i.peer_new_digests),
    }
}

// ---- Ed25519 keys / signatures (spec §2, §5) -------------------------------

/// Generate a new node keypair. Returns the 32-byte private seed (keep at 0600,
/// never share) and the 32-byte public key (goes to the roster).
pub fn keygen() -> Result<([u8; 32], [u8; 32]), &'static str> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|_| "rng_failed")?;
    let sk = SigningKey::from_bytes(&seed);
    Ok((seed, sk.verifying_key().to_bytes()))
}

/// Public key for a given private seed.
pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Sign a 32-byte `root` with the node's private seed → 64-byte Ed25519 signature.
pub fn sign_root(seed: &[u8; 32], root: &[u8; 32]) -> [u8; 64] {
    let sk = SigningKey::from_bytes(seed);
    let sig: Signature = sk.sign(root);
    sig.to_bytes()
}

/// Verify a 64-byte signature over `root` against a 32-byte public key. Invalid
/// public keys or signatures return `false` (never panic).
pub fn verify_root(pubkey: &[u8; 32], root: &[u8; 32], sig: &[u8; 64]) -> bool {
    let vk = match VerifyingKey::from_bytes(pubkey) {
        Ok(vk) => vk,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(sig);
    vk.verify(root, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> CoreFields {
        CoreFields {
            doc_digest: [1; 32],
            prev_digest: [2; 32],
            workflow_id: "wf".to_string(),
            step_index: 5,
            issuer: "did:ex".to_string(),
            nonce: [7; 16],
            roster_epoch: 3,
            meta_digest: [9; 32],
            ring_digest: [11; 32],
        }
    }

    #[test]
    fn canonical_bytes_exact_framing_and_length() {
        let b = sample().canonical_bytes();
        // total = sum over fields of (2 + name + 4 + value)
        // 48 + 49 + 19 + 24 + 18 + 27 + 26 + 49 (meta) + 49 (ring) = 309
        assert_eq!(b.len(), 309);
        // ring_digest (field 9) is present and framed
        let r = b.windows(11).position(|w| w == b"ring_digest").unwrap();
        assert_eq!(&b[r + 11..r + 15], &[0x00, 0x00, 0x00, 0x20]); // len4(value)=32
        // first field: doc_digest (name len 10), value 32 bytes of 1
        assert_eq!(&b[0..2], &[0x00, 0x0A]); // len2(name)=10
        assert_eq!(&b[2..12], b"doc_digest");
        assert_eq!(&b[12..16], &[0x00, 0x00, 0x00, 0x20]); // len4(value)=32
        assert_eq!(&b[16..48], &[1u8; 32]);
        // step_index value is big-endian u64
        let s = b.windows(10).position(|w| w == b"step_index").unwrap();
        let val = &b[s + 10 + 4..s + 10 + 4 + 8];
        assert_eq!(val, &5u64.to_be_bytes());
    }

    #[test]
    fn root_is_deterministic_and_sensitive() {
        let a = sample().root();
        assert_eq!(a, sample().root());
        let mut other = sample();
        other.step_index = 6;
        assert_ne!(a, other.root(), "changing a field must change root");
        // domain separation: raw blake3 over canonical bytes != root
        let raw = *blake3::hash(&sample().canonical_bytes()).as_bytes();
        assert_ne!(a, raw, "root must include the domain prefix");
    }

    #[test]
    fn bridge_maps_interval_to_core_fields() {
        let peers = vec!["tl-0".to_string(), "tl-1".to_string()];
        let mk = |iref: [u8; 32]| {
            let inputs = IntervalInputs {
                interval_ref: iref,
                prev_interval_ref: [0; 32],
                cohort_id: "trial10",
                issued_at_pos: 42,
                issuer_node_id: "tl-3",
                nonce: [1; 16],
                roster_epoch: 7,
                local_digest: [2; 32],
                shadow_digest: [3; 32],
                replay_params: b"rp",
                peers: &peers,
                ring_indices: &[0, 1],
                peer_new_digests: &[[8; 32], [9; 32]],
            };
            core_fields_from_interval(&inputs)
        };
        let cf = mk([5; 32]);
        assert_eq!(cf.doc_digest, [5; 32]);
        assert_eq!(cf.workflow_id, "trial10");
        assert_eq!(cf.step_index, 42);
        assert_eq!(cf.issuer, "tl-3");
        assert_eq!(cf.roster_epoch, 7);
        assert_eq!(cf.meta_digest, meta_digest(&[2; 32], &[3; 32], b"rp"));
        assert_eq!(cf.ring_digest, ring_digest(&peers, &[0, 1], &[[8; 32], [9; 32]]));
        // deterministic; different content -> different root
        assert_eq!(cf.root(), mk([5; 32]).root());
        assert_ne!(cf.root(), mk([6; 32]).root());
    }

    #[test]
    fn derived_digests_deterministic_and_sensitive() {
        let m1 = meta_digest(&[1; 32], &[2; 32], b"rp");
        assert_eq!(m1, meta_digest(&[1; 32], &[2; 32], b"rp"));
        assert_ne!(m1, meta_digest(&[1; 32], &[2; 32], b"rq"));
        assert_ne!(m1, meta_digest(&[1; 32], &[9; 32], b"rp"));

        let peers = vec!["tl-0".to_string(), "tl-1".to_string()];
        let r1 = ring_digest(&peers, &[3, 4], &[[5; 32], [6; 32]]);
        assert_eq!(r1, ring_digest(&peers, &[3, 4], &[[5; 32], [6; 32]]));
        // order matters (ring structure/order is part of the notarial transport)
        let peers_rev = vec!["tl-1".to_string(), "tl-0".to_string()];
        assert_ne!(r1, ring_digest(&peers_rev, &[4, 3], &[[6; 32], [5; 32]]));
    }

    #[test]
    fn sign_verify_roundtrip_and_tamper() {
        let (seed, pk) = keygen().unwrap();
        assert_eq!(public_key(&seed), pk);
        let root = sample().root();
        let sig = sign_root(&seed, &root);
        assert!(verify_root(&pk, &root, &sig), "valid signature must verify");

        // tampered root -> fails
        let mut bad_root = root;
        bad_root[0] ^= 1;
        assert!(!verify_root(&pk, &bad_root, &sig));

        // wrong key -> fails
        let (_seed2, pk2) = keygen().unwrap();
        assert!(!verify_root(&pk2, &root, &sig));

        // garbage pubkey -> false, no panic
        assert!(!verify_root(&[0xFF; 32], &root, &sig));
    }
}
