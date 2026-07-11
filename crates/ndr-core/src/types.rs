//! Shared plain-data types used across the crate and serialized to JSON.

use serde::{Deserialize, Serialize};
use std::fmt;

/// A Windows GUID / UUID, stored in the mixed-endian on-disk layout Windows
/// uses: `Data1` (u32 LE), `Data2`/`Data3` (u16 LE), then 8 raw bytes.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

impl Guid {
    /// Parse from the 16-byte on-disk representation.
    pub fn from_le_bytes(b: [u8; 16]) -> Self {
        Guid {
            data1: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
            data2: u16::from_le_bytes([b[4], b[5]]),
            data3: u16::from_le_bytes([b[6], b[7]]),
            data4: [b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]],
        }
    }

    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.data1.to_le_bytes());
        out[4..6].copy_from_slice(&self.data2.to_le_bytes());
        out[6..8].copy_from_slice(&self.data3.to_le_bytes());
        out[8..16].copy_from_slice(&self.data4);
        out
    }

    pub fn is_zero(&self) -> bool {
        self.data1 == 0 && self.data2 == 0 && self.data3 == 0 && self.data4 == [0; 8]
    }
}

impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7],
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Guid({self})")
    }
}

/// An interface version, as it appears in `RPC_SYNTAX_IDENTIFIER`
/// (`SyntaxVersion`): major in the low 16 bits, minor in the high 16 bits of a
/// little-endian `u32`... in practice MIDL stores them as two `u16`s.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Version {
    pub major: u16,
    pub minor: u16,
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl fmt::Debug for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "v{self}")
    }
}
