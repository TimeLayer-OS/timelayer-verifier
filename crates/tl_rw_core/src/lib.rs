use tl_canon_types::{
    canonical_entry, decode_canonical_entry, CanonBytes, CanonEntry, CanonError, CanonPayload,
    CanonReader, CanonWriter, DigestRef, Epoch, Tick,
};
use tl_digest::{digest_entry, interval_digest, Digest};

const MAX_HISTORY_FRAGMENT_ENTRIES: u64 = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TemporalContext {
    pub tick: Tick,
    pub epoch: Epoch,
    pub previous_digest: DigestRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delta {
    pub payload: CanonPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RwAction {
    pub payload: CanonPayload,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RwTransition {
    pub context: TemporalContext,
    pub action: RwAction,
    pub delta: Delta,
    pub digest: DigestRef,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RwResult {
    pub transition: RwTransition,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct History {
    pub entries: Vec<CanonEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HistoryFragment {
    pub entries: Vec<CanonEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MadState {
    pub digest: DigestRef,
    pub len: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RwCoreError {
    DigestMismatch,
    EmptyFragment,
    Canon(CanonError),
    PartialTransition,
}

impl From<CanonError> for RwCoreError {
    fn from(value: CanonError) -> Self {
        Self::Canon(value)
    }
}

impl HistoryFragment {
    pub fn canonical_bytes(&self) -> CanonBytes {
        encode_history_fragment(self)
    }
}

pub fn execute_rw(ctx: &TemporalContext, action: &RwAction) -> Result<RwResult, RwCoreError> {
    let entry = canonical_entry(ctx.tick, action.payload.clone(), Some(ctx.previous_digest));
    let digest = digest_entry(&entry).as_ref();
    let transition = RwTransition {
        context: ctx.clone(),
        action: action.clone(),
        delta: Delta {
            payload: action.payload.clone(),
        },
        digest,
    };
    Ok(RwResult { transition })
}

pub fn append_history(history: &mut History, transition: RwTransition) -> Result<(), RwCoreError> {
    if transition.action.payload != transition.delta.payload {
        return Err(RwCoreError::PartialTransition);
    }
    let entry = canonical_entry(
        transition.context.tick,
        transition.delta.payload,
        Some(transition.context.previous_digest),
    );
    let digest = digest_entry(&entry).as_ref();
    if digest != transition.digest {
        return Err(RwCoreError::DigestMismatch);
    }
    history.entries.push(entry);
    Ok(())
}

pub fn replay_fragment(fragment: &HistoryFragment) -> Result<DigestRef, RwCoreError> {
    if fragment.entries.is_empty() {
        return Err(RwCoreError::EmptyFragment);
    }
    Ok(interval_digest(&fragment.entries).as_ref())
}

pub fn replay_fragment_digest(fragment: &HistoryFragment) -> Result<Digest, RwCoreError> {
    replay_fragment(fragment).map(Digest::from)
}

pub fn execute_history(history: &History) -> Result<DigestRef, RwCoreError> {
    replay_fragment(&HistoryFragment {
        entries: history.entries.clone(),
    })
}

pub fn encode_history_fragment(fragment: &HistoryFragment) -> CanonBytes {
    let mut writer = CanonWriter::new();
    writer.push_u64(fragment.entries.len() as u64);
    for entry in &fragment.entries {
        let bytes = entry.canonical_bytes();
        writer.push_bytes(bytes.as_slice());
    }
    writer.finish()
}

pub fn decode_history_fragment(bytes: &[u8]) -> Result<HistoryFragment, RwCoreError> {
    let mut reader = CanonReader::new(bytes);
    let len = reader.read_u64()?;
    if len > MAX_HISTORY_FRAGMENT_ENTRIES {
        return Err(RwCoreError::Canon(CanonError::LengthOverflow));
    }
    let mut entries = Vec::with_capacity(len as usize);
    for _ in 0..len {
        let entry_bytes = reader.read_bytes()?;
        entries.push(decode_canonical_entry(&entry_bytes)?);
    }
    reader.finish()?;
    Ok(HistoryFragment { entries })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tick: u64) -> TemporalContext {
        TemporalContext {
            tick: Tick(tick),
            epoch: Epoch(0),
            previous_digest: DigestRef::default(),
        }
    }

    #[test]
    fn execute_and_replay_are_deterministic() {
        let action = RwAction {
            payload: tl_canon_types::canonical_payload("rw", b"a".to_vec()),
        };
        let rw = execute_rw(&ctx(1), &action).unwrap();
        let mut history = History::default();
        append_history(&mut history, rw.transition).unwrap();
        assert_eq!(
            execute_history(&history).unwrap(),
            execute_history(&history).unwrap()
        );
    }

    #[test]
    fn append_history_rejects_partial_delta() {
        let action = RwAction {
            payload: tl_canon_types::canonical_payload("rw", b"a".to_vec()),
        };
        let mut transition = execute_rw(&ctx(1), &action).unwrap().transition;
        transition.delta.payload = tl_canon_types::canonical_payload("rw", b"b".to_vec());
        assert_eq!(
            append_history(&mut History::default(), transition),
            Err(RwCoreError::PartialTransition)
        );
    }

    #[test]
    fn history_fragment_roundtrip() {
        let entry = canonical_entry(
            Tick(1),
            tl_canon_types::canonical_payload("rw", b"a".to_vec()),
            None,
        );
        let fragment = HistoryFragment {
            entries: vec![entry],
        };
        assert_eq!(
            decode_history_fragment(encode_history_fragment(&fragment).as_slice()).unwrap(),
            fragment
        );
    }
}
