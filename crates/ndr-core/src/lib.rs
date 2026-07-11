//! # ndr-core
//!
//! Static extraction of Windows RPC/DCOM interface and NDR format-string data
//! from PE binaries - the engine behind the `ndr-cli` tool and (later) the
//! Binary Ninja plugin.
//!
//! ## Pipeline
//!
//! 1. [`pe::PeImage`] - load the PE, expose sections + RVA/offset mapping.
//! 2. [`interface::find_interfaces`] - locate candidate RPC interfaces (M1).
//! 3. [`ndr::interpret_interface`] - decode each method's parameters (M2, WIP).
//!
//! [`analyze`] runs the whole pipeline and returns a serializable [`Report`].

pub mod error;
pub mod ffi;
pub mod grammar;
pub mod interface;
pub mod ndr;
pub mod pe;
pub mod types;

pub use error::{NdrError, Result};

use serde::Serialize;

/// Full analysis result for one binary.
#[derive(Debug, Serialize)]
pub struct Report {
    /// Path or label of the analyzed binary.
    pub target: String,
    pub is_64bit: bool,
    pub image_base: u64,
    /// Candidate interfaces (M1).
    pub interfaces: Vec<InterfaceReport>,
}

/// Per-interface analysis result.
#[derive(Debug, Serialize)]
pub struct InterfaceReport {
    #[serde(flatten)]
    pub interface: interface::RpcInterface,
    /// Human-readable interface UUID.
    pub uuid: String,
    /// Decoded procedures (empty until M2; `procedures_status` explains why).
    pub procedures: Vec<ndr::Procedure>,
    /// Status string for the procedure decode attempt.
    pub procedures_status: String,
}

/// Run the full analysis pipeline over an already-loaded image.
pub fn analyze(pe: &pe::PeImage, target: impl Into<String>) -> Report {
    let interfaces = interface::find_interfaces(pe)
        .into_iter()
        .map(|iface| {
            let uuid = iface.interface_id.to_string();
            let (procedures, procedures_status) = match ndr::interpret_interface(pe, &iface) {
                Ok(procs) => (procs, "ok".to_string()),
                Err(e) => (Vec::new(), e.to_string()),
            };
            InterfaceReport {
                interface: iface,
                uuid,
                procedures,
                procedures_status,
            }
        })
        .collect();

    Report {
        target: target.into(),
        is_64bit: pe.is_64bit,
        image_base: pe.image_base,
        interfaces,
    }
}

/// Convenience: load a file from disk and analyze it.
pub fn analyze_path<P: AsRef<std::path::Path>>(path: P) -> Result<Report> {
    let label = path.as_ref().display().to_string();
    let pe = pe::PeImage::from_path(path)?;
    Ok(analyze(&pe, label))
}

/// Build a fuzzing grammar (M4) for every interface in a report that has
/// decoded procedures.
pub fn grammars_for_report(report: &Report) -> Vec<grammar::FuzzGrammar> {
    report
        .interfaces
        .iter()
        .filter(|ir| !ir.procedures.is_empty())
        .map(|ir| grammar::build_interface_grammar(&ir.uuid, ir.interface.version, &ir.procedures))
        .collect()
}
