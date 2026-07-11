//! Minimal PE loader tailored to what the NDR extractor needs.
//!
//! We do not need a full loader - just enough to:
//!   * tell 32- vs 64-bit apart (this changes NDR pointer/struct sizing),
//!   * enumerate sections and their raw bytes,
//!   * convert between RVAs (how the binary references its own data) and file
//!     offsets (how we index into the on-disk bytes), and
//!   * read little-endian scalars and GUIDs at a given RVA.
//!
//! The `object` crate does the header parsing; we copy out just the section
//! table so `PeImage` can own its bytes without lifetime entanglement.

use crate::error::{NdrError, Result};
use crate::types::Guid;
use object::read::pe::{PeFile32, PeFile64};
use object::{FileKind, LittleEndian as LE};

/// One PE section, with both its in-memory (RVA) and on-disk (raw) placement.
#[derive(Debug, Clone)]
pub struct Section {
    pub name: String,
    /// Relative virtual address (offset from image base once loaded).
    pub virtual_address: u32,
    pub virtual_size: u32,
    /// Offset of this section's bytes within the on-disk file.
    pub raw_offset: u32,
    pub raw_size: u32,
}

impl Section {
    /// Does this section contain `rva` within its virtual extent?
    fn contains_rva(&self, rva: u32) -> bool {
        rva >= self.virtual_address
            && (rva as u64) < self.virtual_address as u64 + self.virtual_size as u64
    }
}

/// A loaded PE image that owns its bytes.
#[derive(Debug)]
pub struct PeImage {
    data: Vec<u8>,
    pub is_64bit: bool,
    pub image_base: u64,
    pub sections: Vec<Section>,
}

impl PeImage {
    pub fn from_path<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(data)
    }

    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let (is_64bit, image_base, sections) = match FileKind::parse(&*data)? {
            FileKind::Pe32 => {
                let pe = PeFile32::parse(&*data)?;
                let base = pe.nt_headers().optional_header.image_base.get(LE) as u64;
                (false, base, collect_sections(&pe)?)
            }
            FileKind::Pe64 => {
                let pe = PeFile64::parse(&*data)?;
                let base = pe.nt_headers().optional_header.image_base.get(LE);
                (true, base, collect_sections(&pe)?)
            }
            other => {
                return Err(NdrError::Unsupported(format!(
                    "not a PE image (file kind: {other:?})"
                )));
            }
        };

        Ok(Self {
            data,
            is_64bit,
            image_base,
            sections,
        })
    }

    /// Native pointer width in bytes for this image (4 or 8). NDR marshals
    /// pointers and some alignment-sensitive structures at native width.
    pub fn pointer_size(&self) -> usize {
        if self.is_64bit {
            8
        } else {
            4
        }
    }

    /// Map an RVA to an offset into the on-disk file bytes, if it falls inside
    /// a section's raw data. Returns `None` for RVAs that live only in virtual
    /// space (e.g. uninitialized `.bss`-style regions with no raw backing).
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        let sec = self.sections.iter().find(|s| s.contains_rva(rva))?;
        let delta = rva - sec.virtual_address;
        if delta >= sec.raw_size {
            // Inside virtual size but past what's stored on disk.
            return None;
        }
        Some(sec.raw_offset as usize + delta as usize)
    }

    /// Borrow `len` bytes starting at `rva`.
    pub fn bytes_at_rva(&self, rva: u32, len: usize) -> Result<&[u8]> {
        let off = self
            .rva_to_offset(rva)
            .ok_or(NdrError::RvaOutOfRange { rva: rva as u64 })?;
        self.bytes_at_offset(off, len)
    }

    /// Borrow `len` bytes starting at a raw file offset.
    pub fn bytes_at_offset(&self, offset: usize, len: usize) -> Result<&[u8]> {
        let end = offset.checked_add(len).ok_or(NdrError::OffsetOutOfRange {
            offset,
            len,
            size: self.data.len(),
        })?;
        self.data
            .get(offset..end)
            .ok_or(NdrError::OffsetOutOfRange {
                offset,
                len,
                size: self.data.len(),
            })
    }

    pub fn read_u16_at_rva(&self, rva: u32) -> Result<u16> {
        let b = self.bytes_at_rva(rva, 2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn read_u32_at_rva(&self, rva: u32) -> Result<u32> {
        let b = self.bytes_at_rva(rva, 4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn read_u64_at_rva(&self, rva: u32) -> Result<u64> {
        let b = self.bytes_at_rva(rva, 8)?;
        let mut a = [0u8; 8];
        a.copy_from_slice(&b[..8]);
        Ok(u64::from_le_bytes(a))
    }

    /// Read a native-width pointer value stored at `rva`. The stored value is a
    /// virtual address; callers usually subtract `image_base` to get an RVA.
    pub fn read_ptr_at_rva(&self, rva: u32) -> Result<u64> {
        if self.is_64bit {
            self.read_u64_at_rva(rva)
        } else {
            Ok(self.read_u32_at_rva(rva)? as u64)
        }
    }

    pub fn read_guid_at_rva(&self, rva: u32) -> Result<Guid> {
        let b = self.bytes_at_rva(rva, 16)?;
        Ok(Guid::from_le_bytes(b.try_into().expect("checked 16 bytes")))
    }

    /// All section bytes, paired with the section they came from, for scanning.
    pub fn section_slices(&self) -> impl Iterator<Item = (&Section, &[u8])> {
        self.sections.iter().filter_map(move |s| {
            let start = s.raw_offset as usize;
            let end = start.checked_add(s.raw_size as usize)?;
            let bytes = self.data.get(start..end)?;
            Some((s, bytes))
        })
    }
}

/// Copy the section table out of an `object` PE view into owned `Section`s.
/// Works over both PE widths via the `PeSections` adapter below.
fn collect_sections<'d, Pe>(pe: &Pe) -> Result<Vec<Section>>
where
    Pe: PeSections<'d>,
{
    Ok(pe.owned_sections())
}

/// Small internal adapter so `collect_sections` works over both PE widths
/// without duplicating the section-table walk.
trait PeSections<'d> {
    fn owned_sections(&self) -> Vec<Section>;
}

macro_rules! impl_pe_sections {
    ($ty:ty) => {
        impl<'d> PeSections<'d> for $ty {
            fn owned_sections(&self) -> Vec<Section> {
                self.section_table()
                    .iter()
                    .map(|sec| Section {
                        name: String::from_utf8_lossy(&sec.name)
                            .trim_end_matches('\0')
                            .to_string(),
                        virtual_address: sec.virtual_address.get(LE),
                        virtual_size: sec.virtual_size.get(LE),
                        raw_offset: sec.pointer_to_raw_data.get(LE),
                        raw_size: sec.size_of_raw_data.get(LE),
                    })
                    .collect()
            }
        }
    };
}

impl_pe_sections!(PeFile32<'d>);
impl_pe_sections!(PeFile64<'d>);
