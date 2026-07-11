//! Locate candidate RPC interfaces in a PE (milestone M1).
//!
//! Every MIDL-generated stub embeds an `RPC_SERVER_INTERFACE` (server side) or
//! `RPC_CLIENT_INTERFACE` (client side) structure. Both begin the same way:
//!
//! ```c
//! typedef struct {
//!   unsigned int          Length;         // +0x00  sizeof(the struct)
//!   RPC_SYNTAX_IDENTIFIER InterfaceId;    // +0x04  GUID(16) + version(4)
//!   RPC_SYNTAX_IDENTIFIER TransferSyntax; // +0x18  GUID(16) + version(4)
//!   ...
//! }
//! ```
//!
//! `TransferSyntax` almost always identifies the DCE **NDR** transfer syntax
//! (`8a885d04-...`, v2.0) or **NDR64** (`71710533-...`, v1.0). Those GUIDs are
//! fixed, well-known 16-byte constants - an excellent anchor to scan for. Once
//! we find one, the interface's own UUID/version sit at a fixed negative offset
//! from it, and the `TransferSyntax` version dword right after the GUID gives us
//! a cheap validity check.
//!
//! This is a heuristic: a hit is a *candidate*. Confirming it (and following
//! `DispatchTable` / `InterpreterInfo` into the format strings) is M2's job.

use crate::pe::{PeImage, Section};
use crate::types::{Guid, Version};
use serde::Serialize;

/// Offsets within the `RPC_*_INTERFACE` header, relative to the start of the
/// `TransferSyntax.SyntaxGUID` field (our scan anchor).
mod layout {
    /// `Length` sits 24 bytes before the transfer-syntax GUID
    /// (4 for Length + 16 for InterfaceId GUID + 4 for InterfaceId version).
    pub const LENGTH_BACK: usize = 24;
    /// `InterfaceId.SyntaxGUID` sits 20 bytes before the transfer GUID.
    pub const INTERFACE_GUID_BACK: usize = 20;
    /// `InterfaceId.SyntaxVersion` sits 4 bytes before the transfer GUID.
    pub const INTERFACE_VERSION_BACK: usize = 4;
    /// `TransferSyntax.SyntaxVersion` sits 16 bytes after the transfer GUID.
    pub const TRANSFER_VERSION_FWD: usize = 16;
}

/// Which transfer syntax anchored a given interface hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransferSyntax {
    /// DCE NDR, `8a885d04-1ceb-11c9-9fe8-08002b104860`, expected version 2.0.
    Ndr,
    /// Microsoft NDR64, `71710533-beba-4937-8319-b5dbef9ccc36`, version 1.0.
    Ndr64,
}

impl TransferSyntax {
    fn guid(self) -> Guid {
        match self {
            // 8a885d04-1ceb-11c9-9fe8-08002b104860
            TransferSyntax::Ndr => Guid {
                data1: 0x8a88_5d04,
                data2: 0x1ceb,
                data3: 0x11c9,
                data4: [0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60],
            },
            // 71710533-beba-4937-8319-b5dbef9ccc36
            TransferSyntax::Ndr64 => Guid {
                data1: 0x7171_0533,
                data2: 0xbeba,
                data3: 0x4937,
                data4: [0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36],
            },
        }
    }

    /// The `TransferSyntax.SyntaxVersion` these are always paired with.
    fn expected_version(self) -> Version {
        match self {
            TransferSyntax::Ndr => Version { major: 2, minor: 0 },
            TransferSyntax::Ndr64 => Version { major: 1, minor: 0 },
        }
    }

    fn all() -> [TransferSyntax; 2] {
        [TransferSyntax::Ndr, TransferSyntax::Ndr64]
    }
}

/// A candidate RPC interface recovered from the binary.
#[derive(Debug, Clone, Serialize)]
pub struct RpcInterface {
    /// The interface's own UUID (from `InterfaceId.SyntaxGUID`).
    pub interface_id: Guid,
    /// The interface version (from `InterfaceId.SyntaxVersion`).
    pub version: Version,
    /// Which transfer syntax anchored the match.
    pub transfer_syntax: TransferSyntax,
    /// RVA of the `Length` field, i.e. the start of the `RPC_*_INTERFACE`.
    pub struct_rva: u32,
    /// Value of the `Length` field (should be `sizeof` the struct).
    pub struct_len: u32,
    /// Name of the section the structure was found in (usually `.rdata`).
    pub section: String,
}

// String forms are convenient for JSON consumers and for humans; keep the
// numeric fields too so downstream tools don't have to re-parse.
impl RpcInterface {
    pub fn interface_id_string(&self) -> String {
        self.interface_id.to_string()
    }
}

/// Scan a PE for candidate RPC interfaces.
pub fn find_interfaces(pe: &PeImage) -> Vec<RpcInterface> {
    let mut out = Vec::new();

    for ts in TransferSyntax::all() {
        let pattern = ts.guid().to_le_bytes();
        for (sec, bytes) in pe.section_slices() {
            for pos in find_all(bytes, &pattern) {
                if let Some(iface) = try_recover(pe, sec, bytes, pos, ts) {
                    out.push(iface);
                }
            }
        }
    }

    // A client and server stub in the same binary can reference the same
    // interface; collapse exact duplicates but keep distinct versions/RVAs.
    out.sort_by_key(|i| i.struct_rva);
    out.dedup_by(|a, b| a.struct_rva == b.struct_rva);
    out
}

/// Given a transfer-GUID hit at `pos` inside `bytes` (a single section's raw
/// data), validate the surrounding `RPC_*_INTERFACE` header and pull out the
/// interface identity. Returns `None` if it doesn't look like a real header.
fn try_recover(
    pe: &PeImage,
    sec: &Section,
    bytes: &[u8],
    pos: usize,
    ts: TransferSyntax,
) -> Option<RpcInterface> {
    // Need enough bytes before the anchor for the Length + InterfaceId fields,
    // and 4 bytes after for the transfer-syntax version.
    if pos < layout::LENGTH_BACK {
        return None;
    }
    let ver_off = pos + layout::TRANSFER_VERSION_FWD;
    if ver_off + 4 > bytes.len() {
        return None;
    }

    // Validate the transfer-syntax version dword - the cheap high-signal check.
    let transfer_ver = read_version(&bytes[ver_off..ver_off + 4]);
    if transfer_ver != ts.expected_version() {
        return None;
    }

    let iface_guid_off = pos - layout::INTERFACE_GUID_BACK;
    let iface_ver_off = pos - layout::INTERFACE_VERSION_BACK;
    let length_off = pos - layout::LENGTH_BACK;

    let interface_id =
        Guid::from_le_bytes(bytes[iface_guid_off..iface_guid_off + 16].try_into().ok()?);
    // An all-zero interface UUID is almost certainly a false positive (the NDR
    // GUID happened to appear as loose data, not inside a real header).
    if interface_id.is_zero() {
        return None;
    }
    let version = read_version(&bytes[iface_ver_off..iface_ver_off + 4]);
    let struct_len = u32::from_le_bytes(bytes[length_off..length_off + 4].try_into().ok()?);

    // `Length` is `sizeof(RPC_SERVER_INTERFACE)`, which is a fixed value per
    // pointer width: 0x44 on x86, 0x60 on x64. Requiring the exact canonical
    // size is a strong, cheap filter against false positives (the NDR GUID
    // appearing as loose data in a COM/other binary), which otherwise show up
    // with junk lengths like 0x93 / 0xc8 and a broken interpreter chain.
    let expected_len: u32 = if pe.is_64bit { 0x60 } else { 0x44 };
    if struct_len != expected_len {
        return None;
    }

    let struct_rva = sec.virtual_address + length_off as u32;
    // Sanity: the RVA should round-trip back to a readable offset.
    let _ = pe.rva_to_offset(struct_rva)?;

    Some(RpcInterface {
        interface_id,
        version,
        transfer_syntax: ts,
        struct_rva,
        struct_len,
        section: sec.name.clone(),
    })
}

/// Read an `RPC_VERSION` (two little-endian u16s: major then minor).
fn read_version(b: &[u8]) -> Version {
    Version {
        major: u16::from_le_bytes([b[0], b[1]]),
        minor: u16::from_le_bytes([b[2], b[3]]),
    }
}

/// All start indices where `needle` occurs in `haystack` (non-overlapping is
/// irrelevant here - the 16-byte GUID can't overlap itself meaningfully).
fn find_all(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    let mut hits = Vec::new();
    if needle.is_empty() || haystack.len() < needle.len() {
        return hits;
    }
    let first = needle[0];
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        // Fast-forward to the next possible first-byte match.
        match haystack[i..haystack.len() - needle.len() + 1]
            .iter()
            .position(|&b| b == first)
        {
            Some(rel) => {
                let idx = i + rel;
                if &haystack[idx..idx + needle.len()] == needle {
                    hits.push(idx);
                }
                i = idx + 1;
            }
            None => break,
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_all_locates_all_occurrences() {
        let hay = b"xxABxxABAB";
        assert_eq!(find_all(hay, b"AB"), vec![2, 6, 8]);
        assert_eq!(find_all(hay, b"zz"), Vec::<usize>::new());
    }

    #[test]
    fn ndr_guid_bytes_are_canonical() {
        // 8a885d04-1ceb-11c9-9fe8-08002b104860
        let g = TransferSyntax::Ndr.guid();
        assert_eq!(g.to_string(), "8a885d04-1ceb-11c9-9fe8-08002b104860");
    }

    #[test]
    fn ndr64_guid_bytes_are_canonical() {
        let g = TransferSyntax::Ndr64.guid();
        assert_eq!(g.to_string(), "71710533-beba-4937-8319-b5dbef9ccc36");
    }
}
