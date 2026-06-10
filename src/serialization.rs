//! Versioned record serialization helper.
//!
//! Wraps postcard-encoded records with a magic-byte and version-byte header
//! (`b"HWCR" || version || postcard_bytes`) so persisted crypto state can be
//! validated and migrated across format versions.

use serde::{Deserialize, Serialize};

use crate::error::{CryptoError, Result};

const MAGIC: &[u8; 4] = b"HWCR";
const CURRENT_VERSION: u8 = 1;

/// Serialize a record with the hushwire-crypto header.
///
/// Format: `b"HWCR" || version_byte || postcard_bytes`
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let body = postcard::to_allocvec(value)?;
    let mut buf = Vec::with_capacity(5 + body.len());
    buf.extend_from_slice(MAGIC);
    buf.push(CURRENT_VERSION);
    buf.extend_from_slice(&body);
    Ok(buf)
}

/// Deserialize a record with version-prefix validation.
pub fn deserialize<'a, T: Deserialize<'a>>(data: &'a [u8]) -> Result<T> {
    if data.len() < 5 {
        return Err(CryptoError::Serialization("data too short".into()));
    }
    if &data[..4] != MAGIC {
        return Err(CryptoError::Serialization("invalid magic bytes".into()));
    }
    let version = data[4];
    if version != CURRENT_VERSION {
        return Err(CryptoError::Serialization(format!(
            "unsupported version: {version}"
        )));
    }
    Ok(postcard::from_bytes(&data[5..])?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestRecord {
        field_a: u32,
        field_b: Vec<u8>,
        field_c: String,
    }

    #[test]
    fn serialize_deserialize_roundtrip() {
        let record = TestRecord {
            field_a: 42,
            field_b: vec![1, 2, 3],
            field_c: "hello".into(),
        };
        let data = serialize(&record).unwrap();
        let restored: TestRecord = deserialize(&data).unwrap();
        assert_eq!(record, restored);
    }

    #[test]
    fn header_format() {
        let record = 123u32;
        let data = serialize(&record).unwrap();
        assert_eq!(&data[..4], b"HWCR");
        assert_eq!(data[4], CURRENT_VERSION);
    }

    #[test]
    fn too_short_data_fails() {
        assert!(deserialize::<u32>(&[0u8; 4]).is_err());
        assert!(deserialize::<u32>(&[]).is_err());
    }

    #[test]
    fn wrong_magic_fails() {
        let mut data = serialize(&42u32).unwrap();
        data[0] = b'X';
        assert!(deserialize::<u32>(&data).is_err());
    }

    #[test]
    fn wrong_version_fails() {
        let mut data = serialize(&42u32).unwrap();
        data[4] = 99;
        assert!(deserialize::<u32>(&data).is_err());
    }

    #[test]
    fn corrupt_body_fails() {
        let mut data = serialize(&TestRecord {
            field_a: 1,
            field_b: vec![],
            field_c: "x".into(),
        })
        .unwrap();
        data.truncate(6);
        assert!(deserialize::<TestRecord>(&data).is_err());
    }

    #[test]
    fn overhead_is_5_bytes() {
        let value = 42u8;
        let raw = postcard::to_allocvec(&value).unwrap();
        let wrapped = serialize(&value).unwrap();
        assert_eq!(wrapped.len(), raw.len() + 5);
    }
}
