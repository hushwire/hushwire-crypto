//! Protocol addressing: a user UUID paired with a numeric device id.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

use crate::types::DeviceId;

/// Protocol address identifying a specific device belonging to a specific user.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProtocolAddress {
    user_id: Uuid,
    device_id: DeviceId,
}

impl ProtocolAddress {
    /// Builds an address from a user UUID and device id.
    pub fn new(user_id: impl Into<Uuid>, device_id: impl Into<DeviceId>) -> Self {
        Self {
            user_id: user_id.into(),
            device_id: device_id.into(),
        }
    }

    /// Returns the user UUID component.
    pub fn user_id(&self) -> Uuid {
        self.user_id
    }

    /// Returns the device id component.
    pub fn device_id(&self) -> DeviceId {
        self.device_id
    }
}

impl fmt::Display for ProtocolAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.user_id, self.device_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construction_and_accessors() {
        let id = Uuid::new_v4();
        let addr = ProtocolAddress::new(id, 1u32);
        assert_eq!(addr.user_id(), id);
        assert_eq!(addr.device_id(), DeviceId::from(1));
    }

    #[test]
    fn display() {
        let id = Uuid::nil();
        let addr = ProtocolAddress::new(id, 3u32);
        assert_eq!(addr.to_string(), format!("{}:3", Uuid::nil()));
    }

    #[test]
    fn equality() {
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let a = ProtocolAddress::new(alice, 1u32);
        let b = ProtocolAddress::new(alice, 1u32);
        let c = ProtocolAddress::new(alice, 2u32);
        let d = ProtocolAddress::new(bob, 1u32);
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn hash_consistency() {
        use std::collections::HashSet;
        let id = Uuid::new_v4();
        let a = ProtocolAddress::new(id, 1u32);
        let b = ProtocolAddress::new(id, 1u32);
        let mut set = HashSet::new();
        set.insert(a);
        assert!(set.contains(&b));
    }

    #[test]
    fn serde_roundtrip() {
        let addr = ProtocolAddress::new(Uuid::new_v4(), 42u32);
        let bytes = postcard::to_allocvec(&addr).unwrap();
        let restored: ProtocolAddress = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(addr, restored);
    }
}
