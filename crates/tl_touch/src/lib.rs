use tl_canon_types::{CohortId, IntervalId, NodeId, RingId};
use tl_digest::{ring_touch_digest, Digest};
use tl_invariants::{StopState, StopStateReason};

pub const DEFAULT_TOUCH_WINDOW_CAPACITY: usize = 5;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct RingHead {
    pub head_digest: Digest,
    pub ring_depth: u64,
    pub window_start: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TouchReceipt {
    pub ring_index: u64,
    pub prev_digest: Digest,
    pub interval_ref: Digest,
    pub peers: Vec<NodeId>,
    pub new_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TouchWindow {
    pub head: RingHead,
    pub receipts: Vec<TouchReceipt>,
    pub capacity: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TouchRound {
    pub cohort_id: CohortId,
    pub interval_id: IntervalId,
    pub receipts: Vec<TouchReceipt>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TimeCircle {
    pub ring_id: RingId,
    pub previous_digest: Digest,
    pub circle_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TouchState {
    pub node_id: NodeId,
    pub current_digest: Digest,
    pub ring_id: RingId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TouchError {
    InvalidCapacity,
    PreviousDigestMismatch,
    Divergence,
}

impl TouchWindow {
    pub fn new(capacity: usize) -> Result<Self, TouchError> {
        if capacity == 0 {
            return Err(TouchError::InvalidCapacity);
        }
        Ok(Self {
            head: RingHead::default(),
            receipts: Vec::new(),
            capacity,
        })
    }

    pub fn operational_count(&self) -> usize {
        self.receipts.len()
    }
}

impl Default for TouchWindow {
    fn default() -> Self {
        Self::new(DEFAULT_TOUCH_WINDOW_CAPACITY).unwrap_or(Self {
            head: RingHead::default(),
            receipts: Vec::new(),
            capacity: DEFAULT_TOUCH_WINDOW_CAPACITY,
        })
    }
}

pub fn apply_interval_touch(
    window: &mut TouchWindow,
    interval_ref: Digest,
    peers: Vec<NodeId>,
) -> Result<TouchReceipt, TouchError> {
    if window.capacity == 0 {
        return Err(TouchError::InvalidCapacity);
    }
    let ring_index = window.head.ring_depth + 1;
    let prev_digest = window.head.head_digest;
    let new_digest = ring_touch_digest(&prev_digest, &interval_ref, &peers, ring_index);
    let receipt = TouchReceipt {
        ring_index,
        prev_digest,
        interval_ref,
        peers,
        new_digest,
    };
    window.receipts.push(receipt.clone());
    window.head.head_digest = new_digest;
    window.head.ring_depth = ring_index;
    if window.receipts.len() > window.capacity {
        window.receipts.remove(0);
        window.head.window_start += 1;
    }
    verify_ring_continuity(window)?;
    Ok(receipt)
}

pub fn verify_ring_continuity(window: &TouchWindow) -> Result<(), TouchError> {
    if window.receipts.len() > window.capacity {
        return Err(TouchError::Divergence);
    }
    for idx in 1..window.receipts.len() {
        if window.receipts[idx].prev_digest != window.receipts[idx - 1].new_digest {
            return Err(TouchError::Divergence);
        }
    }
    if let Some(last) = window.receipts.last() {
        if window.head.head_digest != last.new_digest {
            return Err(TouchError::Divergence);
        }
        if window.head.ring_depth != last.ring_index {
            return Err(TouchError::Divergence);
        }
    }
    Ok(())
}

pub fn touch_stop_state(error: &TouchError) -> StopState {
    StopState {
        required: matches!(
            error,
            TouchError::Divergence | TouchError::PreviousDigestMismatch
        ),
        reason: if matches!(
            error,
            TouchError::Divergence | TouchError::PreviousDigestMismatch
        ) {
            Some(StopStateReason::Divergence)
        } else {
            None
        },
    }
}

pub fn ping_touch(from: NodeId, to: NodeId, state: &TouchState) -> TouchReceipt {
    let peers = vec![from, to];
    let ring_index = state.ring_id.0 + 1;
    let interval_ref = state.current_digest;
    let new_digest = ring_touch_digest(&state.current_digest, &interval_ref, &peers, ring_index);
    TouchReceipt {
        ring_index,
        prev_digest: state.current_digest,
        interval_ref,
        peers,
        new_digest,
    }
}

pub fn pong_touch(from: NodeId, to: NodeId, state: &TouchState) -> TouchReceipt {
    ping_touch(from, to, state)
}

pub fn apply_touch(
    state: &mut TouchState,
    receipt: &TouchReceipt,
) -> Result<TimeCircle, TouchError> {
    if receipt.prev_digest != state.current_digest {
        return Err(TouchError::PreviousDigestMismatch);
    }
    state.current_digest = receipt.new_digest;
    state.ring_id = RingId(receipt.ring_index);
    Ok(TimeCircle {
        ring_id: RingId(receipt.ring_index),
        previous_digest: receipt.prev_digest,
        circle_digest: receipt.new_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn touch_window_enforces_capacity() {
        let mut window = TouchWindow::new(2).unwrap();
        for idx in 0..3 {
            apply_interval_touch(
                &mut window,
                Digest([idx; 32]),
                vec![NodeId("n".to_string())],
            )
            .unwrap();
        }
        assert_eq!(window.receipts.len(), 2);
        assert_eq!(window.head.window_start, 1);
    }

    #[test]
    fn apply_touch_rejects_previous_digest_mismatch() {
        let state = TouchState {
            node_id: NodeId("n".to_string()),
            current_digest: Digest([1; 32]),
            ring_id: RingId(0),
        };
        let receipt = ping_touch(NodeId("a".to_string()), NodeId("b".to_string()), &state);
        let mut wrong = TouchState {
            current_digest: Digest([2; 32]),
            ..state
        };
        assert_eq!(
            apply_touch(&mut wrong, &receipt),
            Err(TouchError::PreviousDigestMismatch)
        );
    }

    #[test]
    fn touch_digest_is_deterministic() {
        let mut left = TouchWindow::default();
        let mut right = TouchWindow::default();
        let peers = vec![NodeId("n".to_string())];
        let a = apply_interval_touch(&mut left, Digest([7; 32]), peers.clone()).unwrap();
        let b = apply_interval_touch(&mut right, Digest([7; 32]), peers).unwrap();
        assert_eq!(a.new_digest, b.new_digest);
    }
}
