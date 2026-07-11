//! Error types for ndr-core.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum NdrError {
    #[error("i/o error: {0}")]
    Io(#[from] std::io::Error),

    #[error("failed to parse PE object: {0}")]
    Object(#[from] object::Error),

    #[error("unsupported binary: {0}")]
    Unsupported(String),

    /// An RVA could not be mapped to any section in the file.
    #[error("RVA {rva:#x} is not contained in any section")]
    RvaOutOfRange { rva: u64 },

    /// A file offset was requested past the end of the mapped data.
    #[error("offset {offset:#x} (len {len}) is out of bounds (file size {size})")]
    OffsetOutOfRange {
        offset: usize,
        len: usize,
        size: usize,
    },
}

pub type Result<T> = std::result::Result<T, NdrError>;
