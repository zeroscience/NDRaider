//! `ndr-cli` - command-line front-end over `ndr-core`.
//!
//! A thin wrapper: all real work lives in the library so the CLI and the future
//! Binary Ninja plugin share one implementation.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ndr-cli",
    about = "Static RPC/DCOM NDR interface extractor",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a PE binary for candidate RPC interfaces.
    Scan {
        /// Path to the PE file (.dll/.exe) to analyze.
        path: PathBuf,

        /// Emit the full report as JSON instead of a human summary.
        #[arg(long)]
        json: bool,

        /// With --json, pretty-print instead of a single line.
        #[arg(long, requires = "json")]
        pretty: bool,
    },

    /// Emit a structure-aware fuzzing grammar (JSON) for a PE's interfaces.
    Grammar {
        /// Path to the PE file (.dll/.exe) to analyze.
        path: PathBuf,

        /// Single-line JSON instead of pretty-printed.
        #[arg(long)]
        compact: bool,
    },

    /// Recursively scan a directory for PE files that host RPC/MIDL stubs.
    Sweep {
        /// Directory to walk (recursively).
        dir: PathBuf,

        /// Comma-separated file extensions to consider (case-insensitive).
        #[arg(long, default_value = "dll,exe,sys,ocx,cpl,drv,acm,efi")]
        ext: String,

        /// Try every file regardless of extension (slower).
        #[arg(long)]
        all_files: bool,

        /// Also decode and count methods per file (slower).
        #[arg(long)]
        methods: bool,

        /// Only report files with at least this many interfaces.
        #[arg(long, default_value_t = 1)]
        min: usize,

        /// Emit results as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Diagnostic: dump the raw NDR type format string (offset/opcode) per
    /// interface. Useful for validating the interpreter against real binaries.
    DumpTypes {
        /// Path to the PE file (.dll/.exe) to analyze.
        path: PathBuf,

        /// Only dump the interface at this index (default: all).
        #[arg(long)]
        interface: Option<usize>,

        /// Max bytes to dump per interface.
        #[arg(long, default_value_t = 256)]
        len: usize,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { path, json, pretty } => scan(path, json, pretty),
        Command::Grammar { path, compact } => grammar(path, compact),
        Command::Sweep {
            dir,
            ext,
            all_files,
            methods,
            min,
            json,
        } => sweep(dir, ext, all_files, methods, min, json),
        Command::DumpTypes {
            path,
            interface,
            len,
        } => dump_types(path, interface, len),
    }
}

/// One directory-sweep hit.
struct SweepHit {
    path: PathBuf,
    is_64bit: bool,
    interfaces: usize,
    methods: Option<usize>,
}

fn sweep(
    dir: PathBuf,
    ext: String,
    all_files: bool,
    methods: bool,
    min: usize,
    json: bool,
) -> Result<()> {
    if !dir.is_dir() {
        anyhow::bail!("{} is not a directory", dir.display());
    }

    // Normalize the extension allow-list to lowercase.
    let exts: Vec<String> = ext
        .split(',')
        .map(|s| s.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let mut files = Vec::new();
    walk(&dir, &mut files);

    let want_ext = |p: &std::path::Path| -> bool {
        if all_files {
            return true;
        }
        match p.extension().and_then(|e| e.to_str()) {
            Some(e) => exts.iter().any(|x| x == &e.to_ascii_lowercase()),
            None => false,
        }
    };

    let mut scanned = 0usize;
    let mut hits: Vec<SweepHit> = Vec::new();
    for f in files.iter().filter(|f| want_ext(f)) {
        // Non-PE files (and unreadable ones) are simply skipped.
        let Ok(pe) = ndr_core::pe::PeImage::from_path(f) else {
            continue;
        };
        scanned += 1;
        let ifaces = ndr_core::interface::find_interfaces(&pe);
        if ifaces.len() < min {
            continue;
        }
        let method_count = if methods {
            Some(
                ndr_core::analyze(&pe, f.display().to_string())
                    .interfaces
                    .iter()
                    .map(|ir| ir.procedures.len())
                    .sum(),
            )
        } else {
            None
        };
        hits.push(SweepHit {
            path: f.clone(),
            is_64bit: pe.is_64bit,
            interfaces: ifaces.len(),
            methods: method_count,
        });
    }

    // Most interesting (most interfaces) first.
    hits.sort_by(|a, b| b.interfaces.cmp(&a.interfaces).then(a.path.cmp(&b.path)));

    if json {
        let arr: Vec<serde_json::Value> = hits
            .iter()
            .map(|h| {
                serde_json::json!({
                    "path": h.path.display().to_string(),
                    "arch": if h.is_64bit { "x64" } else { "x86" },
                    "interfaces": h.interfaces,
                    "methods": h.methods,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    println!(
        "Swept {} - {scanned} PE file(s) scanned, {} with >= {min} interface(s)\n",
        dir.display(),
        hits.len()
    );
    if hits.is_empty() {
        return Ok(());
    }
    println!(
        "{:>10}  {:>7}  {:<4}  PATH",
        "INTERFACES", "METHODS", "ARCH"
    );
    for h in &hits {
        let m = h
            .methods
            .map(|n| n.to_string())
            .unwrap_or_else(|| "-".into());
        let arch = if h.is_64bit { "x64" } else { "x86" };
        println!(
            "{:>10}  {:>7}  {:<4}  {}",
            h.interfaces,
            m,
            arch,
            h.path.display()
        );
    }
    Ok(())
}

/// Recursively collect regular files under `dir`. Directory symlinks are not
/// followed (avoids loops); unreadable directories are skipped.
fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in rd.flatten() {
        let Ok(ft) = entry.file_type() else { continue };
        let path = entry.path();
        if ft.is_dir() {
            walk(&path, out);
        } else if ft.is_file() {
            out.push(path);
        }
        // symlinks are skipped
    }
}

fn dump_types(path: PathBuf, only: Option<usize>, len: usize) -> Result<()> {
    let pe = ndr_core::pe::PeImage::from_path(&path)
        .with_context(|| format!("loading {}", path.display()))?;
    let ifaces = ndr_core::interface::find_interfaces(&pe);
    for (idx, iface) in ifaces.iter().enumerate() {
        if let Some(want) = only {
            if want != idx {
                continue;
            }
        }
        let Some((rva, bytes)) = ndr_core::ndr::interp::type_format_blob(&pe, iface) else {
            continue;
        };
        println!(
            "\n== interface [{idx}] {}  type fmt @ {rva:#010x} ==",
            iface.interface_id
        );
        let n = len.min(bytes.len());
        for (off, &fc) in bytes[..n].iter().enumerate() {
            println!(
                "  {off:>4}: {fc:#04x}  {}",
                ndr_core::ndr::opcodes::fc_name(fc)
            );
        }
    }
    Ok(())
}

fn grammar(path: PathBuf, compact: bool) -> Result<()> {
    let report =
        ndr_core::analyze_path(&path).with_context(|| format!("analyzing {}", path.display()))?;
    let grammars = ndr_core::grammars_for_report(&report);
    let s = if compact {
        serde_json::to_string(&grammars)?
    } else {
        serde_json::to_string_pretty(&grammars)?
    };
    println!("{s}");
    Ok(())
}

fn scan(path: PathBuf, json: bool, pretty: bool) -> Result<()> {
    let report =
        ndr_core::analyze_path(&path).with_context(|| format!("analyzing {}", path.display()))?;

    if json {
        let s = if pretty {
            serde_json::to_string_pretty(&report)?
        } else {
            serde_json::to_string(&report)?
        };
        println!("{s}");
        return Ok(());
    }

    print_summary(&report);
    Ok(())
}

fn print_summary(report: &ndr_core::Report) {
    let arch = if report.is_64bit { "x64" } else { "x86" };
    println!("Target : {}", report.target);
    println!("Arch   : {arch}  (image base {:#x})", report.image_base);
    println!(
        "Found  : {} candidate interface(s)",
        report.interfaces.len()
    );

    if report.interfaces.is_empty() {
        println!("\n(no RPC interfaces located - binary may not host MIDL stubs)");
        return;
    }

    println!();
    for (i, ir) in report.interfaces.iter().enumerate() {
        let iface = &ir.interface;
        println!(
            "[{idx:>2}] {uuid}  v{ver}",
            idx = i,
            uuid = ir.uuid,
            ver = iface.version,
        );
        println!(
            "     transfer={ts:?}  section={sec}  struct@{rva:#010x} (len {len:#x})",
            ts = iface.transfer_syntax,
            sec = iface.section,
            rva = iface.struct_rva,
            len = iface.struct_len,
        );
        if ir.procedures.is_empty() {
            println!("     procedures: {}", ir.procedures_status);
        } else {
            println!("     procedures: {}", ir.procedures.len());
            for p in &ir.procedures {
                let sig = p
                    .params
                    .iter()
                    .filter(|pm| pm.dir != ndr_core::ndr::ParamDir::Return)
                    .map(render_param)
                    .collect::<Vec<_>>()
                    .join(", ");
                let ret = p
                    .params
                    .iter()
                    .find(|pm| pm.dir == ndr_core::ndr::ParamDir::Return)
                    .map(|pm| format!(" -> {}", render_type(&pm.ty)))
                    .unwrap_or_default();
                println!("       [{:>2}] proc({sig}){ret}", p.proc_num);
            }
        }
    }
}

fn render_param(p: &ndr_core::ndr::Param) -> String {
    let dir = match p.dir {
        ndr_core::ndr::ParamDir::In => "in",
        ndr_core::ndr::ParamDir::Out => "out",
        ndr_core::ndr::ParamDir::InOut => "in,out",
        ndr_core::ndr::ParamDir::Return => "ret",
    };
    // A simple-ref adds an implicit top-level pointer - but string/pointer
    // types already render one, so only add it for value types.
    let implicit_ptr = p.simple_ref
        && !matches!(
            p.ty,
            ndr_core::ndr::TypeRef::Str { .. } | ndr_core::ndr::TypeRef::Pointer { .. }
        );
    let star = if implicit_ptr { "*" } else { "" };
    format!("[{dir}] {}{star}", render_type(&p.ty))
}

fn render_type(t: &ndr_core::ndr::TypeRef) -> String {
    use ndr_core::ndr::TypeRef::*;
    match t {
        Base { name, .. } => name.trim_start_matches("FC_").to_lowercase(),
        Str { wide, .. } => {
            if *wide {
                "wchar*".into()
            } else {
                "char*".into()
            }
        }
        Pointer { pointee, .. } => format!("{}*", render_type(pointee)),
        Struct { members, size, .. } => {
            let inner = members
                .iter()
                .map(render_type)
                .collect::<Vec<_>>()
                .join(",");
            format!("struct{{{inner}}}(sz {size})")
        }
        Array {
            element,
            conformance,
            ..
        } => {
            let n = conformance
                .as_ref()
                .map(|c| {
                    // High nibble 0 of raw_type => field-relative (signed)
                    // offset; nibble 2 => param stack offset (positive).
                    if c.raw_type & 0xf0 == 0 {
                        format!("size_is@{}", c.offset as i16)
                    } else {
                        format!("size_is@{:#x}", c.offset)
                    }
                })
                .unwrap_or_else(|| "[]".into());
            format!("{}[{n}]", render_type(element))
        }
        FixedArray {
            element,
            total_size,
            ..
        } => {
            format!("{}[{total_size}]", render_type(element))
        }
        Range {
            base_name,
            min,
            max,
            ..
        } => {
            format!(
                "{}[{min}..{max}]",
                base_name.trim_start_matches("FC_").to_lowercase()
            )
        }
        InterfacePtr { iid, .. } => match iid {
            Some(i) => format!("iface<{i}>*"),
            None => "iface*".into(),
        },
        ContextHandle { .. } => "ctx_handle".into(),
        Union {
            arms, encapsulated, ..
        } => {
            let kind = if *encapsulated { "union" } else { "union_ne" };
            let arms = arms
                .iter()
                .map(|a| format!("{}:{}", a.case_value, render_type(&a.ty)))
                .collect::<Vec<_>>()
                .join("|");
            format!("{kind}{{{arms}}}")
        }
        UserMarshal { wire, .. } => format!("user_marshal<{}>", render_type(wire)),
        Unresolved { name, .. } => name.to_string(),
    }
}
