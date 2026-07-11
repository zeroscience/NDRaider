//! Coverage-guided fuzzing support: static basic-block discovery ([`blocks`])
//! plus a debugger that collects block coverage and catches crashes
//! ([`debugger`]). Windows-only (uses the Win32 debug loop).

pub mod blocks;
pub mod debugger;

pub use debugger::{Coverage, CrashInfo, Debuggee};

use ndr_core::pe::PeImage;
use std::path::Path;

/// Block-leader RVAs plus the `(rva, size)` of each code region to unprotect.
type Instrumentation = (Vec<u32>, Vec<(u32, u32)>);

/// Basic-block leaders + `.text` regions for `module_pe`, or an error if the PE
/// has no code to instrument.
fn blocks_for(module_pe: &Path) -> std::io::Result<Instrumentation> {
    let pe = PeImage::from_path(module_pe).map_err(|e| std::io::Error::other(e.to_string()))?;
    let rvas = blocks::block_rvas(&pe);
    if rvas.is_empty() {
        return Err(std::io::Error::other("no code blocks found to instrument"));
    }
    let regions = debugger::code_regions(&pe);
    Ok((rvas, regions))
}

/// Spawn a server EXE under the debugger and instrument its **main image**.
pub fn instrument_exe(exe: &Path) -> std::io::Result<Debuggee> {
    let (rvas, regions) = blocks_for(exe)?;
    Debuggee::spawn(exe, None, rvas, regions)
}

/// Spawn `exe` and instrument a **named DLL** it loads. `module_pe` is that DLL
/// on disk (to disassemble); `module_name` is its file name (e.g. `Svc.dll`).
pub fn instrument_spawn_dll(
    exe: &Path,
    module_name: &str,
    module_pe: &Path,
) -> std::io::Result<Debuggee> {
    let (rvas, regions) = blocks_for(module_pe)?;
    Debuggee::spawn(exe, Some(module_name.to_string()), rvas, regions)
}

/// Attach to a running process and instrument a module. `module_name = None`
/// instruments the main image; `Some(name)` a loaded DLL. `module_pe` is the
/// on-disk PE of whichever module is being instrumented.
pub fn instrument_attach(
    pid: u32,
    module_name: Option<&str>,
    module_pe: &Path,
) -> std::io::Result<Debuggee> {
    let (rvas, regions) = blocks_for(module_pe)?;
    Debuggee::attach(pid, module_name.map(|s| s.to_string()), rvas, regions)
}
