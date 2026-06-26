use tl_digest::digest_entry;
use tl_rw_core::{replay_fragment, HistoryFragment};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Invariant {
    Dti,
    Mati,
    Tri,
    RwExecutionLaw,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvariantViolation {
    pub invariant: Invariant,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StopState {
    pub required: bool,
    pub reason: Option<StopStateReason>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopStateReason {
    Divergence,
    Drift,
    Reorder,
    Injection,
    Invariant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvariantError {
    Violation(InvariantViolation),
}

pub fn check_dti(fragment: &HistoryFragment) -> Result<(), InvariantViolation> {
    if fragment.entries.is_empty() {
        return Err(violation(Invariant::Dti, "empty history fragment"));
    }
    for idx in 0..fragment.entries.len() {
        if idx > 0 {
            let expected = digest_entry(&fragment.entries[idx - 1]).as_ref();
            if fragment.entries[idx].previous_digest != Some(expected) {
                return Err(violation(Invariant::Dti, "broken previous digest chain"));
            }
            if fragment.entries[idx].tick.0 <= fragment.entries[idx - 1].tick.0 {
                return Err(violation(Invariant::Dti, "non-monotonic tick"));
            }
        }
    }
    Ok(())
}

pub fn check_mati(fragment: &HistoryFragment) -> Result<(), InvariantViolation> {
    if fragment.entries.is_empty() {
        return Err(violation(Invariant::Mati, "empty history fragment"));
    }
    let mut ticks = Vec::new();
    for idx in 0..fragment.entries.len() {
        let entry = &fragment.entries[idx];
        let bytes = entry.canonical_bytes();
        let decoded = tl_canon_types::decode_canonical_entry(bytes.as_slice())
            .map_err(|_| violation(Invariant::Mati, "canonical entry mutation"))?;
        if decoded != *entry {
            return Err(violation(Invariant::Mati, "canonical bytes entry changed"));
        }
        if ticks.contains(&entry.tick.0) {
            return Err(violation(Invariant::Mati, "duplicate causal position"));
        }
        ticks.push(entry.tick.0);
        if idx > 0 {
            let expected = digest_entry(&fragment.entries[idx - 1]).as_ref();
            if entry.previous_digest != Some(expected) {
                return Err(violation(
                    Invariant::Mati,
                    "inserted or mutated entry linkage",
                ));
            }
        }
    }
    Ok(())
}

pub fn check_tri(fragment: &HistoryFragment) -> Result<(), InvariantViolation> {
    if fragment.entries.is_empty() {
        return Err(violation(Invariant::Tri, "empty history fragment"));
    }
    let mut last = None;
    for entry in &fragment.entries {
        if let Some(previous) = last {
            if entry.tick.0 <= previous {
                return Err(violation(Invariant::Tri, "reorder or duplicate tick"));
            }
        }
        last = Some(entry.tick.0);
    }
    Ok(())
}

pub fn check_rw_execution_law(fragment: &HistoryFragment) -> Result<(), InvariantViolation> {
    if fragment.entries.is_empty() {
        return Err(violation(
            Invariant::RwExecutionLaw,
            "empty history fragment",
        ));
    }
    check_dti(fragment).map_err(|_| {
        violation(
            Invariant::RwExecutionLaw,
            "committed transition digest chain mismatch",
        )
    })?;
    replay_fragment(fragment).map(|_| ()).map_err(|_| {
        violation(
            Invariant::RwExecutionLaw,
            "replay of committed history failed",
        )
    })
}

pub fn stop_state_required(violations: &[InvariantViolation]) -> StopState {
    StopState {
        required: !violations.is_empty(),
        reason: if violations.is_empty() {
            None
        } else {
            Some(StopStateReason::Invariant)
        },
    }
}

fn violation(invariant: Invariant, reason: &str) -> InvariantViolation {
    InvariantViolation {
        invariant,
        reason: reason.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tl_canon_types::{canonical_entry, canonical_payload, DigestRef, Tick};

    fn fragment() -> HistoryFragment {
        let first = canonical_entry(
            Tick(1),
            canonical_payload("i", b"a".to_vec()),
            Some(DigestRef::default()),
        );
        let second = canonical_entry(
            Tick(2),
            canonical_payload("i", b"b".to_vec()),
            Some(tl_digest::digest_entry(&first).as_ref()),
        );
        HistoryFragment {
            entries: vec![first, second],
        }
    }

    #[test]
    fn dti_accepts_linked_chain() {
        assert!(check_dti(&fragment()).is_ok());
    }

    #[test]
    fn tri_rejects_duplicate_tick() {
        let mut f = fragment();
        f.entries[1].tick = Tick(1);
        assert!(check_tri(&f).is_err());
    }

    #[test]
    fn stop_state_required_is_deterministic() {
        let v = violation(Invariant::Dti, "x");
        assert_eq!(
            stop_state_required(std::slice::from_ref(&v)),
            stop_state_required(&[v])
        );
    }
}
