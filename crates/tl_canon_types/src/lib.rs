#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CanonBytes(pub Vec<u8>);

impl CanonBytes {
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for CanonBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CanonPayload {
    pub kind: String,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CanonEntry {
    pub tick: Tick,
    pub payload: CanonPayload,
    pub previous_digest: Option<DigestRef>,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct NodeId(pub String);

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CohortId(pub String);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct IntervalId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct RingId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Tick(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Epoch(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct DigestRef(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct IntegrityStampRef(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct ReceiptId(pub u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct CertificateId(pub u64);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CanonError {
    UnexpectedEof,
    InvalidUtf8,
    InvalidTag,
    TrailingBytes,
    LengthOverflow,
}

pub trait Canonical {
    fn canonical_bytes(&self) -> CanonBytes;
}

impl Canonical for CanonPayload {
    fn canonical_bytes(&self) -> CanonBytes {
        let mut writer = CanonWriter::new();
        writer.push_str(&self.kind);
        writer.push_bytes(&self.bytes);
        writer.finish()
    }
}

impl Canonical for CanonEntry {
    fn canonical_bytes(&self) -> CanonBytes {
        let mut writer = CanonWriter::new();
        writer.push_u64(self.tick.0);
        let payload = self.payload.canonical_bytes();
        writer.push_bytes(payload.as_slice());
        writer.push_option_digest_ref(self.previous_digest);
        writer.finish()
    }
}

impl CanonPayload {
    pub fn canonical_bytes(&self) -> CanonBytes {
        <Self as Canonical>::canonical_bytes(self)
    }
}

impl CanonEntry {
    pub fn canonical_bytes(&self) -> CanonBytes {
        <Self as Canonical>::canonical_bytes(self)
    }
}

pub fn canonical_bytes(payload: &CanonPayload) -> CanonBytes {
    payload.canonical_bytes()
}

pub fn canonical_payload(kind: impl Into<String>, bytes: impl Into<Vec<u8>>) -> CanonPayload {
    CanonPayload {
        kind: kind.into(),
        bytes: bytes.into(),
    }
}

pub fn canonical_entry(
    tick: Tick,
    payload: CanonPayload,
    previous_digest: Option<DigestRef>,
) -> CanonEntry {
    CanonEntry {
        tick,
        payload,
        previous_digest,
    }
}

pub fn decode_canonical_payload(bytes: &[u8]) -> Result<CanonPayload, CanonError> {
    let mut reader = CanonReader::new(bytes);
    let payload = CanonPayload {
        kind: reader.read_string()?,
        bytes: reader.read_bytes()?,
    };
    reader.finish()?;
    Ok(payload)
}

pub fn decode_canonical_entry(bytes: &[u8]) -> Result<CanonEntry, CanonError> {
    let mut reader = CanonReader::new(bytes);
    let tick = Tick(reader.read_u64()?);
    let payload_bytes = reader.read_bytes()?;
    let payload = decode_canonical_payload(&payload_bytes)?;
    let previous_digest = reader.read_option_digest_ref()?;
    reader.finish()?;
    Ok(CanonEntry {
        tick,
        payload,
        previous_digest,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct CanonWriter {
    bytes: Vec<u8>,
}

impl CanonWriter {
    pub fn new() -> Self {
        Self { bytes: Vec::new() }
    }

    pub fn push_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn push_bool(&mut self, value: bool) {
        self.push_u8(u8::from(value));
    }

    pub fn push_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_be_bytes());
    }

    pub fn push_bytes(&mut self, value: &[u8]) {
        self.push_u64(value.len() as u64);
        self.bytes.extend_from_slice(value);
    }

    pub fn push_str(&mut self, value: &str) {
        self.push_bytes(value.as_bytes());
    }

    pub fn push_digest_ref(&mut self, value: &DigestRef) {
        self.bytes.extend_from_slice(&value.0);
    }

    pub fn push_option_digest_ref(&mut self, value: Option<DigestRef>) {
        match value {
            Some(digest) => {
                self.push_u8(1);
                self.push_digest_ref(&digest);
            }
            None => self.push_u8(0),
        }
    }

    pub fn finish(self) -> CanonBytes {
        CanonBytes(self.bytes)
    }
}

pub struct CanonReader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> CanonReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    pub fn read_u8(&mut self) -> Result<u8, CanonError> {
        if self.offset >= self.bytes.len() {
            return Err(CanonError::UnexpectedEof);
        }
        let value = self.bytes[self.offset];
        self.offset += 1;
        Ok(value)
    }

    pub fn read_bool(&mut self) -> Result<bool, CanonError> {
        match self.read_u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(CanonError::InvalidTag),
        }
    }

    pub fn read_u64(&mut self) -> Result<u64, CanonError> {
        if self.offset + 8 > self.bytes.len() {
            return Err(CanonError::UnexpectedEof);
        }
        let mut out = [0u8; 8];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + 8]);
        self.offset += 8;
        Ok(u64::from_be_bytes(out))
    }

    pub fn read_bytes(&mut self) -> Result<Vec<u8>, CanonError> {
        let len = self.read_u64()?;
        let len: usize = len.try_into().map_err(|_| CanonError::LengthOverflow)?;
        if self.offset + len > self.bytes.len() {
            return Err(CanonError::UnexpectedEof);
        }
        let out = self.bytes[self.offset..self.offset + len].to_vec();
        self.offset += len;
        Ok(out)
    }

    pub fn read_string(&mut self) -> Result<String, CanonError> {
        String::from_utf8(self.read_bytes()?).map_err(|_| CanonError::InvalidUtf8)
    }

    pub fn read_digest_ref(&mut self) -> Result<DigestRef, CanonError> {
        if self.offset + 32 > self.bytes.len() {
            return Err(CanonError::UnexpectedEof);
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.bytes[self.offset..self.offset + 32]);
        self.offset += 32;
        Ok(DigestRef(out))
    }

    pub fn read_option_digest_ref(&mut self) -> Result<Option<DigestRef>, CanonError> {
        match self.read_u8()? {
            0 => Ok(None),
            1 => Ok(Some(self.read_digest_ref()?)),
            _ => Err(CanonError::InvalidTag),
        }
    }

    pub fn finish(&self) -> Result<(), CanonError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(CanonError::TrailingBytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_payload_roundtrip_is_deterministic() {
        let payload = canonical_payload("unit", b"abc".to_vec());
        assert_eq!(payload.canonical_bytes(), payload.canonical_bytes());
        assert_eq!(
            decode_canonical_payload(payload.canonical_bytes().as_slice()).unwrap(),
            payload
        );
    }

    #[test]
    fn reader_rejects_trailing_bytes() {
        let mut bytes = canonical_payload("unit", b"abc".to_vec())
            .canonical_bytes()
            .0;
        bytes.push(0);
        assert_eq!(
            decode_canonical_payload(&bytes),
            Err(CanonError::TrailingBytes)
        );
    }

    #[test]
    fn entry_roundtrip_preserves_previous_digest() {
        let entry = canonical_entry(
            Tick(1),
            canonical_payload("entry", [1, 2]),
            Some(DigestRef([3; 32])),
        );
        assert_eq!(
            decode_canonical_entry(entry.canonical_bytes().as_slice()).unwrap(),
            entry
        );
    }
}
