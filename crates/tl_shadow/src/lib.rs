use tl_canon_types::DigestRef;
use tl_digest::interval_digest;
use tl_rw_core::{decode_history_fragment, replay_fragment, HistoryFragment, RwCoreError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShadowMode {
    PS,
    DS,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowExec {
    pub mode: ShadowMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShadowResult {
    pub mode: ShadowMode,
    pub shadow_digest: ShadowDigest,
    pub trajectory: ShadowTrajectory,
    pub divergence: Option<DivergenceEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShadowDigest(pub DigestRef);

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct ShadowTrajectory {
    pub steps: Vec<DigestRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DivergenceEvent {
    pub expected: DigestRef,
    pub observed: DigestRef,
    pub location: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShadowError {
    ReplayFailed,
    DecodeFailed,
}

pub fn run_shadow(
    exec: &ShadowExec,
    fragment: &HistoryFragment,
) -> Result<ShadowResult, ShadowError> {
    let digest = replay_fragment(fragment).map_err(map_replay_error)?;
    let trajectory = ShadowTrajectory {
        steps: vec![digest],
    };
    Ok(ShadowResult {
        mode: exec.mode,
        shadow_digest: ShadowDigest(digest),
        trajectory,
        divergence: None,
    })
}

pub fn run_shadow_from_canonical_bytes(
    exec: &ShadowExec,
    bytes: &[u8],
) -> Result<ShadowResult, ShadowError> {
    let fragment = decode_history_fragment(bytes).map_err(|_| ShadowError::DecodeFailed)?;
    let digest = interval_digest(&fragment.entries).as_ref();
    let trajectory = ShadowTrajectory {
        steps: fragment
            .entries
            .iter()
            .map(|entry| tl_digest::digest_entry(entry).as_ref())
            .collect(),
    };
    Ok(ShadowResult {
        mode: exec.mode,
        shadow_digest: ShadowDigest(digest),
        trajectory,
        divergence: None,
    })
}

pub fn compare_shadow_digest(
    local_digest: &DigestRef,
    shadow_digest: &ShadowDigest,
) -> Result<(), DivergenceEvent> {
    if *local_digest == shadow_digest.0 {
        Ok(())
    } else {
        Err(DivergenceEvent {
            expected: *local_digest,
            observed: shadow_digest.0,
            location: "shadow".to_string(),
        })
    }
}

fn map_replay_error(_: RwCoreError) -> ShadowError {
    ShadowError::ReplayFailed
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_canon_types::{canonical_entry, canonical_payload, DigestRef, Tick};
    use tl_rw_core::encode_history_fragment;

    fn fragment() -> HistoryFragment {
        HistoryFragment {
            entries: vec![canonical_entry(
                Tick(1),
                canonical_payload("shadow", b"a".to_vec()),
                Some(DigestRef::default()),
            )],
        }
    }

    #[test]
    fn run_shadow_matches_canonical_bytes_path() {
        let exec = ShadowExec {
            mode: ShadowMode::PS,
        };
        let f = fragment();
        let direct = run_shadow(&exec, &f).unwrap();
        let isolated =
            run_shadow_from_canonical_bytes(&exec, encode_history_fragment(&f).as_slice()).unwrap();
        assert_eq!(direct.shadow_digest, isolated.shadow_digest);
    }

    #[test]
    fn invalid_canonical_bytes_fail() {
        let exec = ShadowExec {
            mode: ShadowMode::PS,
        };
        assert_eq!(
            run_shadow_from_canonical_bytes(&exec, b"bad"),
            Err(ShadowError::DecodeFailed)
        );
    }

    #[test]
    fn compare_shadow_digest_detects_mismatch() {
        assert!(
            compare_shadow_digest(&DigestRef([1; 32]), &ShadowDigest(DigestRef([2; 32]))).is_err()
        );
    }
}
