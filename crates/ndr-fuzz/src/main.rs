//! `ndr-fuzz` - generate structure-aware NDR request buffers from a PE's
//! extracted grammar.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ndr_fuzz::{generate_request, GenConfig, Rng};
use std::path::PathBuf;
use std::time::Duration;

/// A tiny single-line progress spinner on stderr, so the tool visibly "animates"
/// during long phases (endpoint bind-matching, fuzz loops) even without
/// `--verbose`. Auto-disabled when stderr isn't a terminal (piped/redirected) or
/// when verbose narration is on, so it never corrupts captured output.
mod prog {
    use std::io::{IsTerminal, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    static ON: AtomicBool = AtomicBool::new(false);
    static STATE: Mutex<State> = Mutex::new(State {
        frame: 0,
        last_len: 0,
        last: None,
    });
    struct State {
        frame: usize,
        last_len: usize,
        last: Option<Instant>,
    }

    /// Enable the spinner unless verbose is on or stderr is redirected.
    pub fn init(verbose: bool) {
        ON.store(
            !verbose && std::io::stderr().is_terminal(),
            Ordering::Relaxed,
        );
    }

    /// Update the status line (throttled to ~12 fps).
    pub fn set(msg: &str) {
        if !ON.load(Ordering::Relaxed) {
            return;
        }
        let mut s = STATE.lock().unwrap();
        let now = Instant::now();
        if let Some(l) = s.last {
            if now.duration_since(l) < Duration::from_millis(80) {
                return;
            }
        }
        s.last = Some(now);
        let ch = [b'|', b'/', b'-', b'\\'][s.frame % 4] as char;
        s.frame = s.frame.wrapping_add(1);
        let line = format!("{ch} {msg}");
        let pad = s.last_len.saturating_sub(line.chars().count());
        eprint!("\r{line}{}", " ".repeat(pad));
        let _ = std::io::stderr().flush();
        s.last_len = line.chars().count();
    }

    /// Erase the status line (call before printing any permanent output).
    pub fn clear() {
        if !ON.load(Ordering::Relaxed) {
            return;
        }
        let mut s = STATE.lock().unwrap();
        if s.last_len > 0 {
            eprint!("\r{}\r", " ".repeat(s.last_len));
            let _ = std::io::stderr().flush();
            s.last_len = 0;
        }
    }
}

#[derive(Parser)]
#[command(
    name = "ndr-fuzz",
    about = "Structure-aware DCOM/RPC request generator",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
    /// Verbose narration: show what the fuzzer/debugger does and each request sent.
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(Subcommand)]
enum Command {
    /// List interfaces/methods available to fuzz in a PE.
    List { path: PathBuf },

    /// List ALPC ports in the `\RPC Control` object directory (the live
    /// ncalrpc endpoint names), optionally filtered by a name substring.
    AlpcList {
        /// Case-insensitive substring to filter port names (e.g. `lenovo`).
        filter: Option<String>,
        /// Show every object type, not just ALPC Port entries.
        #[arg(long)]
        all: bool,
    },

    /// Diagnostic: probe a local ncalrpc ALPC port (\RPC Control\<endpoint>).
    /// Reports the NTSTATUS - used to bring up the LRPC/ALPC transport.
    AlpcPing {
        /// The ncalrpc endpoint name (e.g. `ndrtestalpc`).
        endpoint: String,
    },

    /// Resolve which process (PID) serves an ncalrpc endpoint - the process to
    /// point `cov-fuzz --attach` at.
    AlpcOwner {
        /// The ncalrpc endpoint name.
        endpoint: String,
    },

    /// Diagnostic: connect to an ncalrpc endpoint and send an LRPC bind probe
    /// for the first interface in `path`, dumping the reply. Used to reverse
    /// the LRPC bind message layout against a known server.
    AlpcBind {
        /// The ncalrpc endpoint name (e.g. `ndrtestalpc`).
        endpoint: String,
        /// PE whose first interface UUID/version to bind.
        path: PathBuf,
    },

    /// Automate the whole pipeline: sweep/scan a file or directory, then
    /// generate (offline) or fuzz (live) every method of every interface.
    Campaign {
        /// A PE file, or a directory to walk recursively.
        path: PathBuf,
        /// Fuzz cases per method.
        #[arg(long, default_value_t = 32)]
        count: u64,
        /// PRNG seed base (each method gets a derived seed).
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Directory-sweep filter: skip binaries with fewer interfaces.
        #[arg(long, default_value_t = 1)]
        min: usize,
        /// Write a fuzz-case corpus under this directory (offline mode).
        #[arg(long)]
        out: Option<PathBuf>,
        /// LIVE: fuzz over ncacn_ip_tcp (host:port). Single-server targets only.
        #[arg(long)]
        target: Option<String>,
        /// LIVE: fuzz over a local ncacn_np named pipe.
        #[arg(long)]
        pipe: Option<String>,
        /// LIVE: fuzz over a local ncalrpc/ALPC endpoint (e.g. `ndrtestalpc`).
        /// LRPC binds implicitly under the caller's token - no --auth needed.
        #[arg(long)]
        alpc: Option<String>,
        /// Authenticate live binds with NTLM (PKT_INTEGRITY). ncacn only.
        #[arg(long)]
        auth: bool,
        /// Content-fuzzing mode: keep every `size_is`/`length_is` consistent so
        /// buffers pass NDR unmarshal and reach the handler - mutates buffer
        /// *contents* instead of desynchronizing lengths. Best for going deep
        /// once you know the transport/handles work.
        #[arg(long)]
        consistent: bool,
        /// Required to send any live traffic.
        #[arg(long)]
        i_am_authorized: bool,
    },

    /// COVERAGE-GUIDED fuzzing: spawn a server EXE under a built-in debugger,
    /// instrument every basic block, and steer mutation by new code coverage -
    /// catching crashes precisely (faulting instruction + the input that did it).
    /// Drives the interface over ncalrpc. Requires --i-am-authorized.
    CovFuzz {
        /// PE to derive the interface/grammar from (the server EXE or its DLL).
        grammar: PathBuf,
        /// ncalrpc/ALPC endpoint the server listens on.
        #[arg(long)]
        alpc: String,
        /// Target mode A: spawn this server EXE under the debugger.
        #[arg(long)]
        spawn: Option<PathBuf>,
        /// Target mode B: attach to this already-running PID (needs matching
        /// privilege; SYSTEM services require an elevated ndr-fuzz).
        #[arg(long)]
        attach: Option<u32>,
        /// Instrument this DLL (by file name, e.g. `Svc.dll`) instead of the
        /// process main image - for interfaces hosted in a loaded DLL.
        #[arg(long)]
        module: Option<String>,
        /// On-disk PE of the module being instrumented. Defaults to the --spawn
        /// EXE for main-image spawn mode; required for --module or --attach.
        #[arg(long = "module-pe")]
        module_pe: Option<PathBuf>,
        /// Total fuzz iterations.
        #[arg(long, default_value_t = 3000)]
        count: u64,
        /// PRNG seed.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Directory to save a crash reproducer (the exact stub) if one is found.
        #[arg(long)]
        out: Option<PathBuf>,
        /// JSON-over-RPC mode: fill byte[] buffers with fuzzed JSON.
        #[arg(long)]
        json: bool,
        /// Directory of example JSON requests to mutate (best with --json).
        #[arg(long)]
        seeds: Option<PathBuf>,
        /// Required: coverage fuzzing spawns/attaches and hammers a live server.
        #[arg(long)]
        i_am_authorized: bool,
    },

    /// AUTOPILOT: enumerate -> identify -> corpus -> (live) discover endpoints,
    /// bind-match, fuzz (optionally coverage-guided), catch crashes -> report.
    /// The whole pipeline (scan/sweep/grammar/gen/alpc-list/alpc-owner/campaign/
    /// cov-fuzz) behind one command. Offline is safe; `--live` sends traffic.
    HailMary {
        /// A PE file, or a directory to enumerate recursively.
        path: PathBuf,
        /// Write the report (and, offline, a corpus) under here (default: cwd).
        #[arg(long)]
        out: Option<PathBuf>,
        /// LIVE: also discover ncalrpc endpoints, bind-match the discovered
        /// interfaces, and fuzz the matches. Requires --i-am-authorized.
        #[arg(long)]
        live: bool,
        /// With --live: attach a coverage debugger to each matched endpoint's
        /// server process (best-effort; needs matching privilege).
        #[arg(long)]
        cov: bool,
        /// JSON-over-RPC mode: fill byte[] buffers with fuzzed JSON (for services
        /// like Lenovo Vantage that carry a JSON command in the RPC buffer).
        #[arg(long)]
        json: bool,
        /// Directory of example JSON requests to mutate (best with --json).
        #[arg(long)]
        seeds: Option<PathBuf>,
        /// Fuzz cases per method (live) / corpus cases per method (offline, capped).
        #[arg(long, default_value_t = 32)]
        count: u64,
        /// PRNG seed base.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Directory-enumeration filter: skip binaries with fewer interfaces.
        #[arg(long, default_value_t = 1)]
        min: usize,
        /// Required to send any live traffic.
        #[arg(long)]
        i_am_authorized: bool,
    },

    /// Replay a saved request stub (e.g. a `crash_*.bin` reproducer) at an
    /// ncalrpc endpoint N times - to confirm a crash reproduces deterministically.
    Replay {
        /// PE to derive the interface UUID/version from.
        grammar: PathBuf,
        /// ncalrpc endpoint to send to.
        #[arg(long)]
        alpc: String,
        /// Opnum to send the stub to (e.g. the `op5` in the crash filename).
        #[arg(long)]
        opnum: u32,
        /// The raw NDR stub file to send.
        #[arg(long)]
        file: PathBuf,
        /// How many times to send it.
        #[arg(long, default_value_t = 1)]
        count: u64,
        /// Required to send live traffic.
        #[arg(long)]
        i_am_authorized: bool,
    },

    /// Generate request buffers for one method (and optionally send them).
    Gen {
        /// PE file (RPC/DCOM server) to derive the grammar from.
        path: PathBuf,
        /// Interface index (see `list`).
        #[arg(long, default_value_t = 0)]
        interface: usize,
        /// Method opnum to generate for.
        #[arg(long)]
        opnum: u32,
        /// Number of fuzz cases to generate.
        #[arg(long, default_value_t = 8)]
        count: u64,
        /// PRNG seed (reproducible).
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Write .bin files to this directory instead of printing hex.
        #[arg(long)]
        out: Option<PathBuf>,
        /// LIVE FUZZING over ncacn_ip_tcp: host:port (e.g. 127.0.0.1:49152).
        /// Requires --i-am-authorized.
        #[arg(long)]
        target: Option<String>,
        /// LIVE FUZZING over a local ncacn_np named pipe (e.g. \pipe\ndrtest).
        /// Requires --i-am-authorized.
        #[arg(long)]
        pipe: Option<String>,
        /// Authenticate the bind with NTLM (current user). Required to reach
        /// handler code - Windows faults unauthenticated calls.
        #[arg(long, default_value_t = false)]
        auth: bool,
        /// Per-request timeout in milliseconds (TCP mode).
        #[arg(long, default_value_t = 3000)]
        timeout_ms: u64,
        /// Safety gate: affirm you are authorized to fuzz the target. Sending
        /// malformed RPC can crash the target service.
        #[arg(long, default_value_t = false)]
        i_am_authorized: bool,
    },

    /// Enumerate the local COM/DCOM class surface from the registry: classes
    /// with an out-of-process server (LocalServer32 = DCOM) or in-proc DLL, with
    /// their ProgID and AppID. The starting point for COM object fuzzing.
    ComList {
        /// Only out-of-process (DCOM / LocalServer32) classes.
        #[arg(long, default_value_t = false)]
        local: bool,
        /// Only OPC (OLE for Process Control) servers - a DCOM-based industrial
        /// automation surface (OPC DA/HDA/AE Classic).
        #[arg(long, default_value_t = false)]
        opc: bool,
        /// Case-insensitive substring filter over name / ProgID / server path.
        filter: Option<String>,
        /// Machine-readable JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Query the RPC endpoint mapper (epmapper) and list every registered
    /// interface UUID and where it's served (protocol sequence + endpoint) -
    /// auto-discovering the local RPC surface, including dynamic TCP ports.
    Epmapper {
        /// Host to query (default: local machine via ncacn_ip_tcp).
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Machine-readable JSON.
        #[arg(long, default_value_t = false)]
        json: bool,
    },

    /// Fuzz a COM/DCOM object's IDispatch methods with mutated VARIANT args.
    /// Targets an out-of-process (LocalServer32) class by default, so a crash
    /// shows up as a server-death HRESULT and never takes down the fuzzer.
    ComFuzz {
        /// CLSID (e.g. {0002DF01-0000-0000-C000-000000000046}) or a ProgID.
        clsid: String,
        /// Invoke attempts per candidate method.
        #[arg(long, default_value_t = 300)]
        count: u64,
        /// PRNG seed.
        #[arg(long, default_value_t = 0)]
        seed: u64,
        /// Also allow an in-process (InProcServer32) class - RISKY: a crash in
        /// the object crashes THIS process. Off by default.
        #[arg(long, default_value_t = false)]
        allow_inproc: bool,
        /// Safety gate: sending mutated Invoke calls can crash the target.
        #[arg(long, default_value_t = false)]
        i_am_authorized: bool,
    },

    /// Toggle Full PageHeap (Application-Verifier-style heap instrumentation)
    /// for a target EXE via the Image File Execution Options registry key, so
    /// heap overflows fault IMMEDIATELY instead of silently corrupting memory.
    /// Writing HKLM needs an ELEVATED shell. Restart the target to take effect.
    Pageheap {
        /// The target EXE (name or full path; only the file name is used).
        image: PathBuf,
        /// Turn Full PageHeap OFF for this image (default is to turn it ON).
        #[arg(long, default_value_t = false)]
        off: bool,
        /// Just print whether PageHeap is currently enabled for this image.
        #[arg(long, default_value_t = false)]
        status: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    ndr_fuzz::set_verbose(cli.verbose);
    prog::init(cli.verbose);
    match cli.command {
        Command::List { path } => list(path),
        Command::AlpcList { filter, all } => alpc_list(filter, all),
        Command::AlpcPing { endpoint } => alpc_ping(endpoint),
        Command::AlpcOwner { endpoint } => alpc_owner(endpoint),
        Command::AlpcBind { endpoint, path } => alpc_bind(endpoint, path),
        Command::Replay {
            grammar,
            alpc,
            opnum,
            file,
            count,
            i_am_authorized,
        } => replay(grammar, alpc, opnum, file, count, i_am_authorized),
        Command::HailMary {
            path,
            out,
            live,
            cov,
            json,
            seeds,
            count,
            seed,
            min,
            i_am_authorized,
        } => hail_mary(HailMaryArgs {
            path,
            out,
            live,
            cov,
            json,
            seeds,
            count,
            seed,
            min,
            i_am_authorized,
        }),
        Command::CovFuzz {
            grammar,
            alpc,
            spawn,
            attach,
            module,
            module_pe,
            count,
            seed,
            out,
            json,
            seeds,
            i_am_authorized,
        } => cov_fuzz(CovFuzzArgs {
            grammar,
            alpc,
            spawn,
            attach,
            module,
            module_pe,
            count,
            seed,
            out,
            json,
            seeds,
            i_am_authorized,
        }),
        Command::Campaign {
            path,
            count,
            seed,
            min,
            out,
            target,
            pipe,
            alpc,
            auth,
            consistent,
            i_am_authorized,
        } => campaign(CampaignArgs {
            path,
            count,
            seed,
            min,
            out,
            target,
            pipe,
            alpc,
            auth,
            consistent,
            i_am_authorized,
        }),
        Command::Gen {
            path,
            interface,
            opnum,
            count,
            seed,
            out,
            target,
            pipe,
            auth,
            timeout_ms,
            i_am_authorized,
        } => gen(GenArgs {
            path,
            interface,
            opnum,
            count,
            seed,
            out,
            target,
            pipe,
            auth,
            timeout_ms,
            i_am_authorized,
        }),
        Command::Pageheap { image, off, status } => pageheap(image, off, status),
        Command::ComList {
            local,
            opc,
            filter,
            json,
        } => com_list(local, opc, filter, json),
        Command::Epmapper { host, json } => epmapper(host, json),
        Command::ComFuzz {
            clsid,
            count,
            seed,
            allow_inproc,
            i_am_authorized,
        } => com_fuzz(clsid, count, seed, allow_inproc, i_am_authorized),
    }
}

// --- minimal COM layout for manual IDispatch::Invoke via windows-sys ---
#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct ComVariant {
    vt: u16,
    _r: [u16; 3],
    val: u64,
}
#[cfg(windows)]
#[repr(C)]
struct ComDispParams {
    rgvarg: *mut ComVariant,
    named: *mut i32,
    c_args: u32,
    c_named: u32,
}
#[cfg(windows)]
#[repr(C)]
struct IDispatchVtbl {
    query_interface: usize,
    add_ref: usize,
    release: unsafe extern "system" fn(*mut core::ffi::c_void) -> u32,
    get_type_info_count: usize,
    get_type_info: usize,
    get_ids_of_names: usize,
    invoke: unsafe extern "system" fn(
        *mut core::ffi::c_void,
        i32,
        *const windows_sys::core::GUID,
        u32,
        u16,
        *mut ComDispParams,
        *mut ComVariant,
        *mut core::ffi::c_void,
        *mut u32,
    ) -> i32,
}
#[cfg(windows)]
#[repr(C)]
struct IDispatchObj {
    vtbl: *const IDispatchVtbl,
}

/// Fuzz a COM object's dispatch methods (out-of-process by default).
#[cfg(windows)]
fn com_fuzz(
    clsid: String,
    count: u64,
    seed: u64,
    allow_inproc: bool,
    authorized: bool,
) -> Result<()> {
    use windows_sys::core::GUID;
    use windows_sys::Win32::Foundation::SysAllocString;
    use windows_sys::Win32::System::Com::{
        CLSIDFromProgID, CLSIDFromString, CoCreateInstance, CoInitializeEx, CLSCTX_LOCAL_SERVER,
        COINIT_APARTMENTTHREADED,
    };

    if !authorized {
        bail!("refusing to fuzz a COM object without --i-am-authorized");
    }

    // IDispatch IID and a null IID for Invoke's reserved riid.
    const IID_IDISPATCH: GUID = GUID {
        data1: 0x0002_0400,
        data2: 0,
        data3: 0,
        data4: [0xC0, 0, 0, 0, 0, 0, 0, 0x46],
    };
    const IID_NULL: GUID = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
    const DISPATCH_METHOD: u16 = 0x1;

    let wide: Vec<u16> = clsid.encode_utf16().chain(std::iter::once(0)).collect();

    let mut rng = Rng::new(seed);
    unsafe {
        let _ = CoInitializeEx(std::ptr::null(), COINIT_APARTMENTTHREADED as u32);

        // Resolve CLSID from a {guid} string or a ProgID.
        let mut cls = GUID { data1: 0, data2: 0, data3: 0, data4: [0; 8] };
        let hr = if clsid.starts_with('{') {
            CLSIDFromString(wide.as_ptr(), &mut cls)
        } else {
            CLSIDFromProgID(wide.as_ptr(), &mut cls)
        };
        if hr < 0 {
            bail!("cannot resolve CLSID/ProgID {clsid} (hr {hr:#010x})");
        }

        let ctx = if allow_inproc {
            CLSCTX_LOCAL_SERVER | windows_sys::Win32::System::Com::CLSCTX_INPROC_SERVER
        } else {
            CLSCTX_LOCAL_SERVER
        };
        let mut obj: *mut core::ffi::c_void = std::ptr::null_mut();
        let hr = CoCreateInstance(&cls, std::ptr::null_mut(), ctx, &IID_IDISPATCH, &mut obj);
        if hr < 0 || obj.is_null() {
            bail!(
                "CoCreateInstance failed (hr {hr:#010x}). The class may not support IDispatch, \
                 not be out-of-process, or need elevation."
            );
        }
        let disp = obj as *mut IDispatchObj;
        let vtbl = &*(*disp).vtbl;
        println!("[com] created {clsid} - fuzzing IDispatch methods (out-of-proc)");

        // A crash in the server surfaces as one of these HRESULTs.
        let server_dead = |hr: i32| -> bool {
            matches!(
                hr as u32,
                0x8007_06BA // RPC_S_SERVER_UNAVAILABLE
                | 0x8007_06BE // RPC_S_CALL_FAILED
                | 0x8007_06BF // RPC_S_CALL_FAILED_DNE
                | 0x8001_0108 // RPC_E_DISCONNECTED
                | 0x8001_0105 // RPC_E_SERVERFAULT
                | 0x8000_FFFF // E_UNEXPECTED
                | 0x8004_01FD // CO_E_OBJNOTCONNECTED
            )
        };

        let mut invoked = 0u64;
        let mut faults = 0u64;
        // Brute-force candidate dispIDs (0..0x60) x count fuzz cases each.
        for dispid in 0i32..0x60 {
            for _ in 0..count {
                // 0..4 fuzzed VARIANT args (Invoke wants them reversed).
                let n = rng.below(5) as usize;
                let mut args: Vec<ComVariant> = (0..n).map(|_| fuzz_variant(&mut rng)).collect();
                let mut params = ComDispParams {
                    rgvarg: if args.is_empty() { std::ptr::null_mut() } else { args.as_mut_ptr() },
                    named: std::ptr::null_mut(),
                    c_args: n as u32,
                    c_named: 0,
                };
                let mut result = ComVariant { vt: 0, _r: [0; 3], val: 0 };
                let mut argerr: u32 = 0;
                let hr = (vtbl.invoke)(
                    obj,
                    dispid,
                    &IID_NULL,
                    0,
                    DISPATCH_METHOD,
                    &mut params,
                    &mut result,
                    std::ptr::null_mut(),
                    &mut argerr,
                );
                invoked += 1;
                // free any BSTRs we allocated
                for a in args.iter_mut() {
                    if a.vt == 8 && a.val != 0 {
                        windows_sys::Win32::Foundation::SysFreeString(a.val as *const u16);
                    }
                }
                if server_dead(hr) {
                    println!(
                        "\n!!! CRASH: server died on dispid {dispid} after {invoked} invoke(s) (hr {hr:#010x})"
                    );
                    (vtbl.release)(obj);
                    return Ok(());
                }
                // 0x80020003 DISP_E_MEMBERNOTFOUND / 0x80020006 UNKNOWNNAME = no such method
                let h = hr as u32;
                if h != 0x8002_0003 && h != 0x8002_0006 {
                    faults += 1;
                }
                let _ = SysAllocString; // (kept for clarity; strings via fuzz_variant)
            }
        }
        (vtbl.release)(obj);
        println!("[com] done: {invoked} invoke(s), {faults} reached a method, no crash.");
    }
    Ok(())
}

/// A fuzzed VARIANT: integers, doubles, nasty BSTRs, booleans, null-ish.
#[cfg(windows)]
fn fuzz_variant(rng: &mut Rng) -> ComVariant {
    use windows_sys::Win32::Foundation::SysAllocString;
    match rng.below(7) {
        0 => ComVariant { vt: 3, _r: [0; 3], val: rng.next_u64() }, // VT_I4
        1 => ComVariant { vt: 5, _r: [0; 3], val: rng.next_u64() }, // VT_R8 (bit pattern)
        2 => ComVariant { vt: 11, _r: [0; 3], val: 0xFFFF }, // VT_BOOL true
        3 => ComVariant { vt: 0, _r: [0; 3], val: 0 },       // VT_EMPTY
        4 => ComVariant { vt: 1, _r: [0; 3], val: 0 },       // VT_NULL
        _ => {
            // VT_BSTR with a nasty string from the dictionary.
            let s = ndr_fuzz::mutate::TOKENS[rng.pick(ndr_fuzz::mutate::TOKENS.len())];
            let mut w: Vec<u16> = s.iter().map(|&b| b as u16).collect();
            w.push(0);
            let bstr = unsafe { SysAllocString(w.as_ptr()) };
            ComVariant { vt: 8, _r: [0; 3], val: bstr as u64 }
        }
    }
}

#[cfg(not(windows))]
fn com_fuzz(_c: String, _n: u64, _s: u64, _i: bool, _a: bool) -> Result<()> {
    bail!("com-fuzz is Windows-only");
}

/// One enumerated COM class.
#[cfg(windows)]
struct ComClass {
    clsid: String,
    name: String,
    inproc: Option<String>,
    local_server: Option<String>,
    appid: Option<String>,
    progid: Option<String>,
    opc: bool,
}

/// Enumerate `HKEY_CLASSES_ROOT\CLSID` for registered COM classes and their
/// servers. Out-of-process (LocalServer32) classes are the DCOM surface;
/// OPC (OLE for Process Control) servers are flagged - a DCOM-based industrial
/// automation surface fuzzable via the COM path.
#[cfg(windows)]
fn com_list(local_only: bool, opc_only: bool, filter: Option<String>, json: bool) -> Result<()> {
    use windows_sys::Win32::Foundation::ERROR_SUCCESS;
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_CLASSES_ROOT, KEY_READ,
    };

    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };

    // Does a class implement one of the OPC component categories (DA/HDA/AE)?
    unsafe fn has_opc_category(clsid: &str) -> bool {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegEnumKeyExW, RegOpenKeyExW, HKEY, HKEY_CLASSES_ROOT, KEY_READ,
        };
        const OPC_CATIDS: &[&str] = &[
            "{63D5F430-CFE4-11D1-B2C8-0060083BA1FB}", // OPC DA 1.0
            "{63D5F432-CFE4-11D1-B2C8-0060083BA1FB}", // OPC DA 2.0
            "{CC603642-66D7-48F1-B69A-B625E73652D7}", // OPC DA 3.0
            "{7DE5B060-E089-11D2-A5E6-000086339399}", // OPC HDA 1.0
            "{58E13251-AC87-11D1-84D5-00608CB8A7E9}", // OPC AE 1.0
        ];
        let sub: Vec<u16> = format!("CLSID\\{clsid}\\Implemented Categories")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut k: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(HKEY_CLASSES_ROOT, sub.as_ptr(), 0, KEY_READ, &mut k) != ERROR_SUCCESS {
            return false;
        }
        let mut idx = 0u32;
        let mut found = false;
        loop {
            let mut nb = [0u16; 64];
            let mut nl = nb.len() as u32;
            if RegEnumKeyExW(
                k,
                idx,
                nb.as_mut_ptr(),
                &mut nl,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            ) != ERROR_SUCCESS
            {
                break;
            }
            idx += 1;
            let cat = String::from_utf16_lossy(&nb[..nl as usize]).to_ascii_uppercase();
            if OPC_CATIDS.contains(&cat.as_str()) {
                found = true;
                break;
            }
        }
        RegCloseKey(k);
        found
    }

    // Read a key's default (unnamed) string value.
    unsafe fn read_default(root: HKEY, sub: &[u16]) -> Option<String> {
        use windows_sys::Win32::Foundation::ERROR_SUCCESS;
        use windows_sys::Win32::System::Registry::{
            RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, KEY_QUERY_VALUE,
        };
        let mut k: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(root, sub.as_ptr(), 0, KEY_QUERY_VALUE, &mut k) != ERROR_SUCCESS {
            return None;
        }
        let mut buf = [0u16; 1024];
        let mut sz = (buf.len() * 2) as u32;
        let mut kind = 0u32;
        let r = RegQueryValueExW(
            k,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut kind,
            buf.as_mut_ptr() as *mut u8,
            &mut sz,
        );
        RegCloseKey(k);
        if r != ERROR_SUCCESS || sz == 0 {
            return None;
        }
        let n = (sz as usize / 2).saturating_sub(1).min(buf.len());
        let s = String::from_utf16_lossy(&buf[..n]);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    let mut classes: Vec<ComClass> = Vec::new();
    unsafe {
        let mut clsid_root: HKEY = std::ptr::null_mut();
        if RegOpenKeyExW(
            HKEY_CLASSES_ROOT,
            wide("CLSID").as_ptr(),
            0,
            KEY_READ,
            &mut clsid_root,
        ) != ERROR_SUCCESS
        {
            bail!("cannot open HKEY_CLASSES_ROOT\\CLSID");
        }
        let mut idx = 0u32;
        loop {
            let mut namebuf = [0u16; 128];
            let mut namelen = namebuf.len() as u32;
            let r = RegEnumKeyExW(
                clsid_root,
                idx,
                namebuf.as_mut_ptr(),
                &mut namelen,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            );
            if r != ERROR_SUCCESS {
                break;
            }
            idx += 1;
            let clsid = String::from_utf16_lossy(&namebuf[..namelen as usize]);
            if !clsid.starts_with('{') {
                continue;
            }
            let base = format!("CLSID\\{clsid}");
            let name = read_default(HKEY_CLASSES_ROOT, &wide(&base)).unwrap_or_default();
            let inproc = read_default(HKEY_CLASSES_ROOT, &wide(&format!("{base}\\InProcServer32")));
            let local_server =
                read_default(HKEY_CLASSES_ROOT, &wide(&format!("{base}\\LocalServer32")));
            let appid = read_default(HKEY_CLASSES_ROOT, &wide(&format!("{base}\\AppID")));
            let progid = read_default(HKEY_CLASSES_ROOT, &wide(&format!("{base}\\ProgID")));

            if inproc.is_none() && local_server.is_none() {
                continue; // no server -> not instantiable
            }
            if local_only && local_server.is_none() {
                continue;
            }
            let mut opc = name.to_ascii_lowercase().contains("opc")
                || progid.as_deref().unwrap_or("").to_ascii_lowercase().contains("opc");
            if !opc {
                opc = has_opc_category(&clsid);
            }
            if opc_only && !opc {
                continue;
            }
            classes.push(ComClass {
                clsid,
                name,
                inproc,
                local_server,
                appid,
                progid,
                opc,
            });
        }
        RegCloseKey(clsid_root);
    }

    if let Some(f) = filter.as_deref() {
        let fl = f.to_ascii_lowercase();
        classes.retain(|c| {
            c.name.to_ascii_lowercase().contains(&fl)
                || c.progid.as_deref().unwrap_or("").to_ascii_lowercase().contains(&fl)
                || c.local_server.as_deref().unwrap_or("").to_ascii_lowercase().contains(&fl)
                || c.inproc.as_deref().unwrap_or("").to_ascii_lowercase().contains(&fl)
        });
    }
    classes.sort_by_key(|c| c.name.to_lowercase());

    if json {
        let arr: Vec<serde_json::Value> = classes
            .iter()
            .map(|c| {
                serde_json::json!({
                    "clsid": c.clsid,
                    "name": c.name,
                    "progid": c.progid,
                    "appid": c.appid,
                    "inproc": c.inproc,
                    "local_server": c.local_server,
                    "dcom": c.local_server.is_some(),
                    "opc": c.opc,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }

    let dcom = classes.iter().filter(|c| c.local_server.is_some()).count();
    let opc = classes.iter().filter(|c| c.opc).count();
    println!(
        "{} COM class(es){}: {dcom} out-of-process (DCOM), {} in-proc only, {opc} OPC\n",
        classes.len(),
        if local_only { " (DCOM only)" } else { "" },
        classes.len() - dcom
    );
    for c in &classes {
        let kind = if c.opc {
            "OPC"
        } else if c.local_server.is_some() {
            "DCOM"
        } else {
            "inproc"
        };
        let prog = c.progid.as_deref().unwrap_or("-");
        let name = if c.name.is_empty() { "(unnamed)" } else { &c.name };
        println!("[{kind:>6}] {}  {name}", c.clsid);
        println!("         progid={prog}");
        if let Some(s) = &c.local_server {
            println!("         server={s}");
        } else if let Some(s) = &c.inproc {
            println!("         dll={s}");
        }
    }
    Ok(())
}

/// Read a NUL-terminated UTF-16 string.
#[cfg(windows)]
unsafe fn wstr(p: *const u16) -> String {
    if p.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *p.add(len) != 0 {
        len += 1;
    }
    String::from_utf16_lossy(std::slice::from_raw_parts(p, len))
}

/// Query the RPC endpoint mapper on `host` and list interface -> endpoint.
#[cfg(windows)]
fn epmapper(host: String, json: bool) -> Result<()> {
    use windows_sys::core::GUID;
    use windows_sys::Win32::System::Rpc::{
        RpcBindingFree, RpcBindingFromStringBindingW, RpcBindingToStringBindingW,
        RpcMgmtEpEltInqBegin, RpcMgmtEpEltInqDone, RpcMgmtEpEltInqNextW, RpcStringBindingComposeW,
        RpcStringFreeW, RPC_IF_ID,
    };
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    const RPC_C_EP_ALL_ELTS: u32 = 0;

    let mut out: Vec<(String, u16, u16, String, String)> = Vec::new();
    unsafe {
        let mut sb: *mut u16 = std::ptr::null_mut();
        let st = RpcStringBindingComposeW(
            std::ptr::null(),
            wide("ncacn_ip_tcp").as_ptr(),
            wide(&host).as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            &mut sb,
        );
        if st != 0 {
            bail!("RpcStringBindingCompose failed ({st})");
        }
        let mut binding: *mut core::ffi::c_void = std::ptr::null_mut();
        let st = RpcBindingFromStringBindingW(sb, &mut binding);
        RpcStringFreeW(&mut sb);
        if st != 0 {
            bail!("RpcBindingFromStringBinding failed ({st})");
        }

        let mut inq: *mut *mut core::ffi::c_void = std::ptr::null_mut();
        let st = RpcMgmtEpEltInqBegin(
            binding,
            RPC_C_EP_ALL_ELTS,
            std::ptr::null(),
            0,
            std::ptr::null(),
            &mut inq,
        );
        if st != 0 {
            RpcBindingFree(&mut binding);
            bail!("RpcMgmtEpEltInqBegin failed ({st}) - is the endpoint mapper reachable on {host}?");
        }

        loop {
            let mut ifid: RPC_IF_ID = std::mem::zeroed();
            let mut obj: GUID = std::mem::zeroed();
            let mut elt: *mut core::ffi::c_void = std::ptr::null_mut();
            let mut ann: *mut u16 = std::ptr::null_mut();
            let st = RpcMgmtEpEltInqNextW(
                inq as *const *const core::ffi::c_void,
                &mut ifid,
                &mut elt,
                &mut obj,
                &mut ann,
            );
            if st != 0 {
                break; // RPC_X_NO_MORE_ENTRIES
            }
            let u = ifid.Uuid;
            let uuid = format!(
                "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                u.data1, u.data2, u.data3, u.data4[0], u.data4[1], u.data4[2], u.data4[3], u.data4[4],
                u.data4[5], u.data4[6], u.data4[7]
            );
            let mut bs: *mut u16 = std::ptr::null_mut();
            let mut bind = String::new();
            if !elt.is_null() && RpcBindingToStringBindingW(elt, &mut bs) == 0 {
                bind = wstr(bs);
                RpcStringFreeW(&mut bs);
            }
            let annotation = if ann.is_null() {
                String::new()
            } else {
                let s = wstr(ann);
                RpcStringFreeW(&mut ann);
                s
            };
            if !elt.is_null() {
                RpcBindingFree(&mut elt);
            }
            out.push((uuid, ifid.VersMajor, ifid.VersMinor, bind, annotation));
        }
        RpcMgmtEpEltInqDone(&mut inq);
        RpcBindingFree(&mut binding);
    }

    if json {
        let arr: Vec<serde_json::Value> = out
            .iter()
            .map(|(u, vmaj, vmin, b, a)| {
                serde_json::json!({"interface": u, "version": format!("{vmaj}.{vmin}"), "binding": b, "annotation": a})
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr)?);
        return Ok(());
    }
    println!("{} endpoint-mapper registration(s) on {host}:\n", out.len());
    for (u, vmaj, vmin, b, a) in &out {
        println!("{u} v{vmaj}.{vmin}");
        println!("   binding: {b}");
        if !a.is_empty() {
            println!("   annotation: {a}");
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn epmapper(_host: String, _json: bool) -> Result<()> {
    bail!("epmapper is Windows-only");
}

#[cfg(not(windows))]
fn com_list(_local: bool, _opc: bool, _filter: Option<String>, _json: bool) -> Result<()> {
    bail!("com-list is Windows-only");
}

/// Enable / disable / query Full PageHeap for an image via Image File Execution
/// Options. Full PageHeap places each heap allocation at the end of a page with
/// an unmapped guard page after it, so any overrun faults IMMEDIATELY - turning
/// silent heap corruption into a catchable access violation.
#[cfg(windows)]
fn pageheap(image: std::path::PathBuf, off: bool, status: bool) -> Result<()> {
    use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HANDLE};
    use windows_sys::Win32::System::Registry::{
        RegCloseKey, RegCreateKeyExW, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW,
        RegSetValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_DWORD,
        REG_OPTION_NON_VOLATILE,
    };

    let name = image
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| image.to_string_lossy().to_string());
    let subkey = format!(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\{name}"
    );
    let wide = |s: &str| -> Vec<u16> { s.encode_utf16().chain(std::iter::once(0)).collect() };
    let wsub = wide(&subkey);

    // FLG_HEAP_PAGE_ALLOCS (0x02000000) in GlobalFlag + PageHeapFlags = 0x3 (full).
    const GLOBAL_FLAG: u32 = 0x0200_0000;
    const PAGEHEAP_FULL: u32 = 0x3;

    unsafe {
        if status {
            let mut hkey: HKEY = std::ptr::null_mut();
            let r = RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                wsub.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut hkey,
            );
            if r != ERROR_SUCCESS {
                println!("PageHeap for {name}: OFF (no IFEO key)");
                return Ok(());
            }
            let mut val: u32 = 0;
            let mut sz: u32 = 4;
            let mut kind: u32 = 0;
            let ok = RegQueryValueExW(
                hkey,
                wide("PageHeapFlags").as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                &mut val as *mut u32 as *mut u8,
                &mut sz,
            ) == ERROR_SUCCESS;
            RegCloseKey(hkey);
            println!(
                "PageHeap for {name}: {}",
                if ok && val != 0 { "ON (full)" } else { "OFF" }
            );
            return Ok(());
        }

        let mut hkey: HKEY = std::ptr::null_mut();
        let r = RegCreateKeyExW(
            HKEY_LOCAL_MACHINE,
            wsub.as_ptr(),
            0,
            std::ptr::null(),
            REG_OPTION_NON_VOLATILE,
            KEY_SET_VALUE | KEY_QUERY_VALUE,
            std::ptr::null(),
            &mut hkey,
            std::ptr::null_mut(),
        );
        if r != ERROR_SUCCESS {
            bail!(
                "cannot open/create the IFEO key (error {r}). Writing HKLM needs an ELEVATED \
                 shell - run this from an Administrator prompt."
            );
        }
        let set = |value: &str, v: u32| -> u32 {
            RegSetValueExW(
                hkey,
                wide(value).as_ptr(),
                0,
                REG_DWORD,
                &v as *const u32 as *const u8,
                4,
            )
        };
        if off {
            RegDeleteValueW(hkey, wide("PageHeapFlags").as_ptr());
            RegDeleteValueW(hkey, wide("GlobalFlag").as_ptr());
            RegCloseKey(hkey as HANDLE);
            println!("PageHeap DISABLED for {name}. Restart the target to take effect.");
        } else {
            let a = set("GlobalFlag", GLOBAL_FLAG);
            let b = set("PageHeapFlags", PAGEHEAP_FULL);
            RegCloseKey(hkey as HANDLE);
            if a != ERROR_SUCCESS || b != ERROR_SUCCESS {
                bail!("failed to write PageHeap values (need elevation).");
            }
            println!(
                "Full PageHeap ENABLED for {name}. Restart the target (or its service) so it \
                 launches under page-heap; then fuzz - heap overruns now fault immediately."
            );
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn pageheap(_image: std::path::PathBuf, _off: bool, _status: bool) -> Result<()> {
    bail!("pageheap is Windows-only");
}

#[cfg(windows)]
fn alpc_list(filter: Option<String>, all: bool) -> Result<()> {
    let entries = ndr_fuzz::alpc::list_object_directory(r"\RPC Control", filter.as_deref())
        .map_err(|s| {
            anyhow::anyhow!(r"NtOpenDirectoryObject(\RPC Control) failed NTSTATUS {s:#010x}")
        })?;
    let mut shown = 0usize;
    for (name, ty) in &entries {
        if !all && ty != "ALPC Port" {
            continue;
        }
        println!("{name}  [{ty}]");
        shown += 1;
    }
    eprintln!(
        "[alpc] {shown} port(s) shown of {} directory entr(y/ies){}",
        entries.len(),
        filter
            .map(|f| format!(" matching \"{f}\""))
            .unwrap_or_default()
    );
    Ok(())
}

#[cfg(not(windows))]
fn alpc_list(_filter: Option<String>, _all: bool) -> Result<()> {
    bail!("ncalrpc/ALPC is only available on Windows")
}

#[cfg(windows)]
fn alpc_ping(endpoint: String) -> Result<()> {
    eprintln!(r"[alpc] connecting to \RPC Control\{endpoint} ...");
    match ndr_fuzz::alpc::AlpcPort::connect(&endpoint, &[]) {
        Ok(_port) => {
            eprintln!("[alpc] connected OK (port handle acquired)");
            Ok(())
        }
        Err(status) => {
            // Report the raw NTSTATUS; some are expected while the LRPC bind
            // isn't built yet (e.g. the server may refuse a payload-less
            // connect), but they still confirm we reached the port.
            eprintln!("[alpc] NtAlpcConnectPort -> NTSTATUS {status:#010x}");
            bail!("connect failed (NTSTATUS {status:#010x})")
        }
    }
}

#[cfg(not(windows))]
fn alpc_ping(_endpoint: String) -> Result<()> {
    bail!("ncalrpc/ALPC is only available on Windows")
}

#[cfg(windows)]
fn alpc_owner(endpoint: String) -> Result<()> {
    let port = ndr_fuzz::alpc::AlpcPort::connect(&endpoint, &[])
        .map_err(|s| anyhow::anyhow!("connect failed NTSTATUS {s:#010x}"))?;
    match port.server_pid() {
        Some(pid) => {
            println!("{endpoint} is served by PID {pid}");
            Ok(())
        }
        None => bail!("could not resolve the server PID for {endpoint}"),
    }
}

#[cfg(not(windows))]
fn alpc_owner(_endpoint: String) -> Result<()> {
    bail!("ncalrpc/ALPC is only available on Windows")
}

#[cfg(windows)]
fn alpc_bind(endpoint: String, path: PathBuf) -> Result<()> {
    let report = ndr_core::analyze_path(&path)?;
    let g = ndr_core::grammars_for_report(&report);
    let g = g.first().context("no interface with methods in the PE")?;
    let (maj, min) = parse_version(&g.version);
    let uuid = ndr_fuzz::dcerpc::parse_uuid(&g.interface).context("bad uuid")?;
    eprintln!("[alpc] connecting to \\RPC Control\\{endpoint} ...");
    let port = ndr_fuzz::alpc::AlpcPort::connect(&endpoint, &[])
        .map_err(|s| anyhow::anyhow!("connect failed NTSTATUS {s:#010x}"))?;
    eprintln!(
        "[alpc] connected; sending LRPC bind probe for {} v{maj}.{min}",
        g.interface
    );
    let bind = ndr_fuzz::alpc::build_bind_message(uuid, maj, min);
    match port.send_receive(&bind) {
        Ok(reply) => {
            let n = reply.len().min(48);
            let hexs: String = reply[..n].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("[alpc] bind reply: {} bytes: {hexs}", reply.len());
            match ndr_fuzz::alpc::parse_bind_reply(&reply) {
                Ok(r) if r.rpc_status == 0 => eprintln!(
                    "[alpc] BIND OK - interface accepted, binding id = {}",
                    r.binding_id
                ),
                Ok(r) => eprintln!("[alpc] bind refused: RpcStatus {:#x}", r.rpc_status),
                Err(e) => eprintln!("[alpc] {e}"),
            }
        }
        Err(s) => eprintln!("[alpc] send_receive -> NTSTATUS {s:#010x}"),
    }
    Ok(())
}

#[cfg(not(windows))]
fn alpc_bind(_endpoint: String, _path: PathBuf) -> Result<()> {
    bail!("ncalrpc/ALPC is only available on Windows")
}

#[cfg(windows)]
fn replay(
    grammar: PathBuf,
    endpoint: String,
    opnum: u32,
    file: PathBuf,
    count: u64,
    authorized: bool,
) -> Result<()> {
    use ndr_fuzz::alpc::{AlpcRpc, CallOutcome};
    if !authorized {
        bail!("replay sends live RPC; pass --i-am-authorized");
    }
    let stub = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
    let gs = grammars(&grammar)?;
    let g = gs
        .into_iter()
        .find(|g| !g.methods.is_empty())
        .context("no interface with methods in the grammar PE")?;
    let (maj, min) = parse_version(&g.version);
    let uuid = ndr_fuzz::dcerpc::parse_uuid(&g.interface).context("bad interface uuid")?;
    let mut rpc = AlpcRpc::bind(&endpoint, uuid, maj, min)
        .map_err(|e| anyhow::anyhow!("bind {} on {endpoint} failed: {e}", g.interface))?;
    eprintln!(
        "[replay] bound {} on {endpoint}; sending {}-byte stub to opnum {opnum} x{count}",
        g.interface,
        stub.len()
    );
    for i in 0..count {
        match rpc.call(opnum, &stub) {
            Ok(CallOutcome::Response(r)) => println!("  #{i}: response ({} bytes)", r.len()),
            Ok(CallOutcome::Fault(s)) => println!("  #{i}: FAULT {s:#x}"),
            Ok(CallOutcome::Skipped) => println!("  #{i}: skipped (stub too large)"),
            Err(s) => {
                println!(
                    "  #{i}: ALPC send failed NTSTATUS {s:#010x} - SERVER LIKELY CRASHED/GONE"
                );
                return Ok(());
            }
        }
    }
    println!("[replay] done - server stayed up across {count} send(s)");
    Ok(())
}

#[cfg(not(windows))]
fn replay(_g: PathBuf, _e: String, _o: u32, _f: PathBuf, _c: u64, _a: bool) -> Result<()> {
    bail!("ncalrpc/ALPC is only available on Windows")
}

struct CovFuzzArgs {
    grammar: PathBuf,
    alpc: String,
    spawn: Option<PathBuf>,
    attach: Option<u32>,
    module: Option<String>,
    module_pe: Option<PathBuf>,
    count: u64,
    seed: u64,
    out: Option<PathBuf>,
    json: bool,
    seeds: Option<PathBuf>,
    i_am_authorized: bool,
}

/// Light byte-level "havoc" on a marshaled stub: a few bit flips / interesting
/// bytes / increments, length-preserving so it still resembles a valid request.
#[cfg(windows)]
fn havoc(base: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut b = base.to_vec();
    if b.is_empty() {
        return b;
    }
    let n = 1 + (rng.next_u64() as usize % 8);
    for _ in 0..n {
        let pos = (rng.next_u64() as usize) % b.len();
        match rng.next_u64() % 4 {
            0 => b[pos] ^= 1u8 << (rng.next_u64() % 8),
            1 => b[pos] = b[pos].wrapping_add(1),
            2 => b[pos] = [0u8, 0xff, 0x7f, 0x80, 0x01][(rng.next_u64() as usize) % 5],
            _ => b[pos] = rng.next_u64() as u8,
        }
    }
    b
}

#[cfg(windows)]
fn cov_fuzz(a: CovFuzzArgs) -> Result<()> {
    use ndr_fuzz::alpc::AlpcRpc;
    use std::time::Instant;

    if !a.i_am_authorized {
        bail!("refusing to spawn+fuzz a live server without --i-am-authorized");
    }
    let gs = grammars(&a.grammar)?;
    let g = gs
        .into_iter()
        .find(|g| !g.methods.is_empty())
        .context("no interface with decoded methods in the grammar PE")?;
    let (maj, minr) = parse_version(&g.version);
    let uuid = ndr_fuzz::dcerpc::parse_uuid(&g.interface).context("bad interface uuid")?;

    // Select the target: spawn an EXE or attach to a PID; instrument the main
    // image or a named DLL.
    if a.spawn.is_some() == a.attach.is_some() {
        bail!("specify exactly one of --spawn <exe> or --attach <pid>");
    }
    if a.module.is_some() && a.module_pe.is_none() {
        bail!("--module <dll> also needs --module-pe <path-to-that-dll-on-disk>");
    }
    let dbg = if let Some(exe) = &a.spawn {
        match (&a.module, &a.module_pe) {
            (Some(name), Some(pe)) => {
                eprintln!("[cov] spawning {}, instrumenting DLL {name}", exe.display());
                ndr_fuzz::cov::instrument_spawn_dll(exe, name, pe)
            }
            _ => {
                eprintln!("[cov] spawning + instrumenting {}", exe.display());
                ndr_fuzz::cov::instrument_exe(exe)
            }
        }
        .with_context(|| format!("failed to spawn/instrument {}", exe.display()))?
    } else {
        let pid = a.attach.unwrap();
        let pe = a
            .module_pe
            .as_ref()
            .context("--attach requires --module-pe <on-disk PE of the module to instrument>")?;
        eprintln!(
            "[cov] attaching to pid {pid}, instrumenting {}",
            a.module.as_deref().unwrap_or("main image")
        );
        ndr_fuzz::cov::instrument_attach(pid, a.module.as_deref(), pe)
            .with_context(|| format!("failed to attach to pid {pid}"))?
    };
    let cov = dbg.coverage().clone();

    // Wait for breakpoints to be installed (CREATE_PROCESS handled).
    let t0 = Instant::now();
    while !cov.ready() && t0.elapsed() < std::time::Duration::from_secs(15) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !cov.ready() || cov.exited() {
        bail!("target failed to start under the debugger");
    }
    eprintln!(
        "[cov] instrumented {} basic blocks; waiting for the server to listen...",
        cov.total()
    );
    // Let the server finish startup (RpcServerListen) under instrumentation.
    std::thread::sleep(std::time::Duration::from_millis(1500));

    let mut rpc = AlpcRpc::bind(&a.alpc, uuid, maj, minr)
        .map_err(|e| anyhow::anyhow!("bind {} on {} failed: {e}", g.interface, a.alpc))?;
    eprintln!(
        "[cov] bound {} v{maj}.{minr} on \\RPC Control\\{} - fuzzing {} method(s)",
        g.interface,
        a.alpc,
        g.methods.len()
    );

    let mut cfg = GenConfig::default();
    if a.json {
        cfg.json_payload = true;
        cfg.json_seeds = load_json_seeds(a.seeds.as_deref());
        eprintln!(
            "[cov] JSON-over-RPC payload mode ({} seed(s))",
            cfg.json_seeds.len()
        );
    }
    let mut rng = Rng::new(a.seed);
    let methods = &g.methods;
    let opener = methods
        .iter()
        .find(|m| method_opens_handle(m))
        .map(|m| m.opnum);
    let mut corpus: Vec<Vec<Vec<u8>>> = vec![Vec::new(); methods.len()];

    let start = cov.covered();
    let mut finds = 0u64;
    let mut crash_case: Option<(u32, Vec<u8>)> = None;
    let mut last_report = Instant::now();

    for iter in 0..a.count {
        if cov.has_crash() || cov.exited() {
            break;
        }
        let mi = (rng.next_u64() as usize) % methods.len();
        let m = &methods[mi];
        let needs = method_needs_handle(m);

        let stub: Vec<u8> = if needs {
            // Handle-gated: regenerate structurally with a fresh live handle
            // (havoc would corrupt the 20-byte handle).
            let mut mcfg = cfg.clone();
            if let Some(op) = opener {
                if let Some(h) = open_handle(&mut rpc, op) {
                    mcfg.context_handle = Some(h);
                }
            }
            generate_request(m, &mut rng, &mcfg)
        } else if !corpus[mi].is_empty() && rng.chance(70, 100) {
            let pick = (rng.next_u64() as usize) % corpus[mi].len();
            havoc(&corpus[mi][pick], &mut rng)
        } else {
            generate_request(m, &mut rng, &cfg)
        };

        let before = cov.covered();
        prog::set(&format!(
            "cov-fuzz iter {}/{} - opnum {} - {} blocks, {finds} new-cov",
            iter + 1,
            a.count,
            m.opnum,
            cov.covered()
        ));
        let res = rpc.call(m.opnum, &stub);
        let after = cov.covered();

        match res {
            Ok(_) => {
                if after > before {
                    finds += 1;
                    if !needs {
                        corpus[mi].push(stub);
                    }
                }
            }
            Err(_) => {
                // The ALPC send/receive failed: the server very likely died on
                // THIS request. Give the debugger a beat to record the exception,
                // then attribute the crash to this exact stub.
                std::thread::sleep(std::time::Duration::from_millis(200));
                crash_case = Some((m.opnum, stub));
                break;
            }
        }

        if last_report.elapsed() > std::time::Duration::from_millis(1500) {
            prog::clear();
            let csize: usize = corpus.iter().map(|c| c.len()).sum();
            eprintln!(
                "[cov] iter {iter:>6}: {} blocks (+{} during fuzz), corpus {csize}, {finds} new-coverage inputs",
                cov.covered(),
                cov.covered().saturating_sub(start)
            );
            last_report = Instant::now();
        }
    }
    prog::clear();

    println!(
        "\n[cov] done: {}/{} blocks covered ({} gained during fuzzing), {finds} coverage-increasing inputs",
        cov.covered(),
        cov.total(),
        cov.covered().saturating_sub(start)
    );

    if let Some(cr) = cov.take_crash() {
        println!("\n!!! CRASH CAUGHT: {}", cr.describe());
        if let Some((opnum, stub)) = &crash_case {
            let hexs: String = stub.iter().map(|b| format!("{b:02x}")).collect();
            println!("    opnum {opnum}, {}-byte stub: {hexs}", stub.len());
            if let Some(dir) = &a.out {
                std::fs::create_dir_all(dir)?;
                let stem = format!("crash_op{opnum}_{:#010x}", cr.rip);
                std::fs::write(dir.join(format!("{stem}.bin")), stub)?;
                std::fs::write(dir.join(format!("{stem}.txt")), cr.report())?;
                println!(
                    "    reproducer + crash report saved: {}\\{stem}.{{bin,txt}}",
                    dir.display()
                );
            }
        } else {
            println!("    (crash not attributable to a single in-flight request)");
        }
        // The full register/stack/backtrace report.
        println!("\n{}", cr.report());
    } else if cov.exited() {
        println!("(server exited during fuzzing - possible crash without a caught exception)");
    } else {
        println!("no crash; the covered handlers held up.");
    }
    Ok(())
}

#[cfg(not(windows))]
fn cov_fuzz(_a: CovFuzzArgs) -> Result<()> {
    bail!("coverage-guided fuzzing (debugger) is only available on Windows")
}

struct CampaignArgs {
    path: PathBuf,
    count: u64,
    seed: u64,
    min: usize,
    out: Option<PathBuf>,
    target: Option<String>,
    pipe: Option<String>,
    alpc: Option<String>,
    auth: bool,
    consistent: bool,
    i_am_authorized: bool,
}

/// Per-method seed so runs are reproducible yet decorrelated across methods.
fn method_seed(base: u64, opnum: u32) -> u64 {
    base ^ (opnum as u64)
        .wrapping_add(1)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
}

fn campaign(a: CampaignArgs) -> Result<()> {
    let live = a.target.is_some() || a.pipe.is_some() || a.alpc.is_some();
    if live && !a.i_am_authorized {
        bail!(
            "refusing to send live traffic without --i-am-authorized.\n\
             Auto-fuzzing sends malformed RPC to every method and can crash the target."
        );
    }

    // Collect target binaries.
    let mut files = Vec::new();
    let is_dir = a.path.is_dir();
    if is_dir {
        walk(&a.path, &mut files);
    } else {
        files.push(a.path.clone());
    }
    const EXTS: &[&str] = &["dll", "exe", "sys", "ocx", "cpl", "drv", "acm", "efi"];
    let want = |p: &std::path::Path| -> bool {
        !is_dir
            || p.extension()
                .and_then(|e| e.to_str())
                .map(|e| EXTS.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false)
    };

    let mut cfg = GenConfig::default();
    if a.consistent {
        // Keep lengths consistent and never oversize, so buffers survive NDR
        // unmarshal and we fuzz handler logic on their contents.
        cfg.keep_length_consistent_pct = 100;
        cfg.oversize_pct = 0;
    }
    let (mut bins, mut total_cases, mut total_faults, mut total_disc) = (0usize, 0u64, 0u64, 0u64);

    eprintln!(
        "[campaign] {} - {} mode{}, {} case(s)/method",
        a.path.display(),
        if live { "LIVE" } else { "offline (generate)" },
        if a.consistent { ", content-fuzz" } else { "" },
        a.count
    );

    for f in files.iter().filter(|f| want(f)) {
        let Ok(report) = ndr_core::analyze_path(f) else {
            continue;
        };
        // In directory mode, honor --min like `ndr-cli sweep`.
        if is_dir && report.interfaces.len() < a.min {
            continue;
        }
        let grammars = ndr_core::grammars_for_report(&report);
        if grammars.is_empty() {
            continue;
        }
        bins += 1;
        println!("\n== {} ==", f.display());

        for g in &grammars {
            let (maj, minr) = parse_version(&g.version);
            if live {
                let uuid = match ndr_fuzz::dcerpc::parse_uuid(&g.interface) {
                    Some(u) => u,
                    None => continue,
                };
                // The transports are different stream types (byte-stream for
                // ncacn, ALPC messages for ncalrpc), so run the per-interface
                // fuzz in each branch and reduce to a common result tuple.
                let result: Result<(u64, u64, u64), String> = if let Some(ep) = &a.alpc {
                    alpc_fuzz_interface(ep, uuid, maj, minr, &g.methods, a.count, a.seed, &cfg)
                } else if let Some(pipe) = &a.pipe {
                    ndr_fuzz::connect_pipe(pipe, uuid, maj, minr, a.auth)
                        .map(|c| fuzz_all_methods(c, &g.methods, a.count, a.seed, &cfg))
                        .map_err(|e| e.to_string())
                } else {
                    let t = a.target.as_ref().unwrap();
                    ndr_fuzz::connect_tcp(t, uuid, maj, minr, Duration::from_millis(3000), a.auth)
                        .map(|c| fuzz_all_methods(c, &g.methods, a.count, a.seed, &cfg))
                        .map_err(|e| e.to_string())
                };
                match result {
                    Ok((cases, faults, disc)) => {
                        total_cases += cases;
                        total_faults += faults;
                        total_disc += disc;
                        let flag = if disc > 0 {
                            "  <-- DISCONNECT (possible crash)"
                        } else {
                            ""
                        };
                        println!(
                            "  {} v{}: {} method(s), {cases} case(s), {faults} fault(s), {disc} disconnect(s){flag}",
                            g.interface, g.version, g.methods.len()
                        );
                    }
                    Err(e) => println!("  {} v{}: [skip] bind failed: {e}", g.interface, g.version),
                }
            } else {
                let uuid8 = g.interface.split('-').next().unwrap_or("iface");
                let mut cases = 0u64;
                for m in &g.methods {
                    let mut rng = Rng::new(method_seed(a.seed, m.opnum));
                    for i in 0..a.count {
                        let buf = generate_request(m, &mut rng, &cfg);
                        cases += 1;
                        if let Some(dir) = &a.out {
                            let stem = f.file_stem().and_then(|s| s.to_str()).unwrap_or("bin");
                            let d = dir.join(stem).join(uuid8).join(format!("op{}", m.opnum));
                            std::fs::create_dir_all(&d)?;
                            std::fs::write(d.join(format!("case_{i:06}.bin")), &buf)?;
                        }
                    }
                }
                total_cases += cases;
                println!(
                    "  {} v{}: {} method(s), {cases} case(s) generated",
                    g.interface,
                    g.version,
                    g.methods.len()
                );
            }
        }
    }

    println!(
        "\n=== campaign done: {bins} binary(ies), {total_cases} case(s){} ===",
        if live {
            format!(", {total_faults} fault(s), {total_disc} disconnect(s)")
        } else {
            String::new()
        }
    );
    if let Some(dir) = &a.out {
        println!("corpus written under {}", dir.display());
    }
    Ok(())
}

/// Fuzz every method of one bound interface; returns (cases, faults, disconnects).
fn fuzz_all_methods<S: std::io::Read + std::io::Write>(
    mut conn: ndr_fuzz::RpcConn<S>,
    methods: &[ndr_core::grammar::MethodGrammar],
    count: u64,
    seed: u64,
    cfg: &GenConfig,
) -> (u64, u64, u64) {
    use ndr_fuzz::Transport;
    let mut cases = 0u64;
    for m in methods {
        let mut rng = Rng::new(method_seed(seed, m.opnum));
        for i in 0..count {
            let buf = generate_request(m, &mut rng, cfg);
            cases += 1;
            if conn.send(m.opnum, i, &buf).is_err() {
                // Connection dropped - likely a crash. Stop this interface.
                return (cases, conn.stats.faults, conn.stats.disconnects.max(1));
            }
        }
    }
    (cases, conn.stats.faults, conn.stats.disconnects)
}

/// Bind one interface over ncalrpc/ALPC and fuzz every method. Windows-only;
/// the non-Windows stub keeps `campaign` compiling on other platforms.
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn alpc_fuzz_interface(
    endpoint: &str,
    uuid: [u8; 16],
    maj: u16,
    min: u16,
    methods: &[ndr_core::grammar::MethodGrammar],
    count: u64,
    seed: u64,
    cfg: &GenConfig,
) -> Result<(u64, u64, u64), String> {
    let rpc = ndr_fuzz::alpc::AlpcRpc::bind(endpoint, uuid, maj, min)?;
    Ok(fuzz_all_methods_alpc(rpc, methods, count, seed, cfg, None))
}

#[cfg(not(windows))]
#[allow(clippy::too_many_arguments)]
fn alpc_fuzz_interface(
    _endpoint: &str,
    _uuid: [u8; 16],
    _maj: u16,
    _min: u16,
    _methods: &[ndr_core::grammar::MethodGrammar],
    _count: u64,
    _seed: u64,
    _cfg: &GenConfig,
) -> Result<(u64, u64, u64), String> {
    Err("ncalrpc/ALPC is only available on Windows".to_string())
}

/// Fuzz every method of a bound LRPC interface; returns (cases, faults,
/// disconnects). An ALPC send failure means the connection died - counted as a
/// disconnect (possible crash) and stops this interface.
/// True if the method's first output is a context handle and it takes none in -
/// i.e. an "opener" that mints a fresh handle (e.g. an `Open`/`Connect`).
#[cfg(windows)]
fn method_opens_handle(m: &ndr_core::grammar::MethodGrammar) -> bool {
    use ndr_core::grammar::Node;
    let returns = matches!(
        m.response.first().map(|f| &f.node),
        Some(Node::ContextHandle)
    );
    returns && !method_needs_handle(m)
}

/// True if any request field is a context handle (the method is handle-gated).
#[cfg(windows)]
fn method_needs_handle(m: &ndr_core::grammar::MethodGrammar) -> bool {
    use ndr_core::grammar::Node;
    m.request
        .iter()
        .any(|f| matches!(f.node, Node::ContextHandle))
}

/// Call an opener opnum once and return the 20-byte context handle it mints
/// (only if non-null). Used to feed handle-gated methods a live handle.
#[cfg(windows)]
fn open_handle(rpc: &mut ndr_fuzz::alpc::AlpcRpc, opener_opnum: u32) -> Option<Vec<u8>> {
    use ndr_fuzz::alpc::CallOutcome;
    // Openers take no in-params, so an empty stub is the correct request.
    if let Ok(CallOutcome::Response(resp)) = rpc.call(opener_opnum, &[]) {
        if resp.len() >= 20 && resp[..20].iter().any(|&b| b != 0) {
            return Some(resp[..20].to_vec());
        }
    }
    None
}

/// If the attached debuggee recorded a crash, save the crashing stub (`.bin`)
/// and a register/stack/backtrace report (`.txt`). Returns true if it saved.
#[cfg(windows)]
fn save_crash_if_any(
    cov: &ndr_fuzz::cov::Coverage,
    dir: &std::path::Path,
    tag: &str,
    opnum: u32,
    stub: &[u8],
) -> bool {
    let Some(cr) = cov.peek_crash() else {
        return false;
    };
    let _ = std::fs::create_dir_all(dir);
    let safe: String = tag
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .take(24)
        .collect();
    let stem = format!("crash_{safe}_op{opnum}_{:#010x}", cr.rip);
    let _ = std::fs::write(dir.join(format!("{stem}.bin")), stub);
    let _ = std::fs::write(dir.join(format!("{stem}.txt")), cr.report());
    prog::clear();
    eprintln!(
        "  [!] CRASH: {} - reproducer + report saved: {}\\{stem}.{{bin,txt}}",
        cr.describe(),
        dir.display()
    );
    true
}

#[cfg(windows)]
fn fuzz_all_methods_alpc(
    mut rpc: ndr_fuzz::alpc::AlpcRpc,
    methods: &[ndr_core::grammar::MethodGrammar],
    count: u64,
    seed: u64,
    cfg: &GenConfig,
    // When coverage-attached: (debuggee coverage, out dir, endpoint tag) so we can
    // save the crashing input + a register/stack crash report.
    crash_out: Option<(&ndr_fuzz::cov::Coverage, &std::path::Path, &str)>,
) -> (u64, u64, u64) {
    use ndr_fuzz::alpc::CallOutcome;
    use std::collections::BTreeMap;
    let (mut cases, mut faults) = (0u64, 0u64);

    // Stateful fuzzing: if the interface has an opener, use it to hand each
    // handle-gated method a *fresh* live context handle so calls reach handler
    // code instead of bouncing off the runtime's handle check (0x6f7).
    let opener = methods
        .iter()
        .find(|m| method_opens_handle(m))
        .map(|m| m.opnum);
    if let Some(op) = opener {
        eprintln!(
            "    [ctx] opnum {op} is an opener - chaining its handle into handle-gated methods"
        );
    }

    // Per-method tally of (responses, distinct fault-status -> count) so a 100%
    // fault rate can be told apart from real handler coverage, and the status
    // reveals *why* (0x6f7 bad stub data vs 0x5 access denied, etc.).
    for m in methods {
        // Give handle-gated methods a fresh live handle (re-opened per method so
        // a close-style method can't invalidate a later one's handle).
        let mut mcfg = cfg.clone();
        let mut chained = false;
        if method_needs_handle(m) {
            if let Some(op) = opener {
                if let Some(h) = open_handle(&mut rpc, op) {
                    mcfg.context_handle = Some(h);
                    chained = true;
                }
            }
        }

        ndr_fuzz::vlog!(
            "fuzzing opnum {} ({} request field(s), {count} case(s){})",
            m.opnum,
            m.request.len(),
            if chained { ", live ctx handle" } else { "" }
        );
        let mut rng = Rng::new(method_seed(seed, m.opnum));
        let mut responses = 0u64;
        let mut skipped = 0u64;
        let mut fault_status: BTreeMap<u32, u64> = BTreeMap::new();
        for i in 0..count {
            let buf = generate_request(m, &mut rng, &mcfg);
            cases += 1;
            prog::set(&format!(
                "fuzzing opnum {} - case {}/{count} ({faults} faults)",
                m.opnum,
                i + 1
            ));
            let res = rpc.call(m.opnum, &buf);
            // If a coverage debugger is attached, a caught crash means THIS input
            // killed the server: save the exact stub + a crash report and stop.
            if let Some((cov, dir, tag)) = crash_out {
                if cov.has_crash() || res.is_err() {
                    std::thread::sleep(Duration::from_millis(200));
                    if save_crash_if_any(cov, dir, tag, m.opnum, &buf) {
                        prog::clear();
                        return (cases, faults, 1);
                    }
                }
            }
            match res {
                Ok(CallOutcome::Fault(s)) => {
                    faults += 1;
                    *fault_status.entry(s).or_insert(0) += 1;
                }
                Ok(CallOutcome::Response(_)) => responses += 1,
                Ok(CallOutcome::Skipped) => skipped += 1,
                Err(_status) => {
                    prog::clear();
                    return (cases, faults, 1);
                }
            }
        }
        prog::clear();
        let faultsum: String = fault_status
            .iter()
            .map(|(s, n)| format!("{s:#x}x{n}"))
            .collect::<Vec<_>>()
            .join(" ");
        eprintln!(
            "    opnum {:>3}{}: {responses} response(s), {} fault(s) [{}]{}",
            m.opnum,
            if chained { " (ctx)" } else { "" },
            fault_status.values().sum::<u64>(),
            if faultsum.is_empty() {
                "-".into()
            } else {
                faultsum
            },
            if skipped > 0 {
                format!(", {skipped} skipped(too-big)")
            } else {
                String::new()
            }
        );
    }
    (cases, faults, 0)
}

/// Recursively collect regular files under `dir` (directory symlinks skipped).
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
    }
}

struct HailMaryArgs {
    path: PathBuf,
    out: Option<PathBuf>,
    live: bool,
    cov: bool,
    json: bool,
    seeds: Option<PathBuf>,
    count: u64,
    seed: u64,
    min: usize,
    i_am_authorized: bool,
}

/// Load + parse a directory of JSON files as a seed corpus for JSON-payload mode.
fn load_json_seeds(dir: Option<&std::path::Path>) -> std::sync::Arc<Vec<serde_json::Value>> {
    let mut v = Vec::new();
    if let Some(d) = dir {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                if let Ok(bytes) = std::fs::read(e.path()) {
                    if let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                        v.push(val);
                    }
                }
            }
        }
    }
    std::sync::Arc::new(v)
}

/// A discovered, fuzzable interface (with its grammar and source binary).
struct Iface {
    uuid_str: String,
    uuid: [u8; 16],
    maj: u16,
    min: u16,
    grammar: ndr_core::grammar::FuzzGrammar,
    source: PathBuf,
}

/// Result of live-fuzzing one matched endpoint.
#[allow(dead_code)]
struct LiveHit {
    endpoint: String,
    uuid: String,
    owner: Option<u32>,
    cases: u64,
    faults: u64,
    disc: u64,
    cov: Option<(usize, usize)>,
    crash: Option<String>,
    crash_report: Option<String>,
}

/// AUTOPILOT. Ties the whole pipeline together behind one command.
fn hail_mary(a: HailMaryArgs) -> Result<()> {
    // 1. Enumerate candidate PEs.
    let is_dir = a.path.is_dir();
    let mut files = Vec::new();
    if is_dir {
        walk(&a.path, &mut files);
    } else {
        files.push(a.path.clone());
    }
    const EXTS: &[&str] = &["dll", "exe", "sys", "ocx", "cpl", "drv", "acm", "efi"];

    // 2. Identify interfaces (dedup by UUID; keep the first source that has it).
    let total_files = files.len();
    let mut ifaces: Vec<Iface> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut bins_with_rpc = 0usize;
    for (fi, f) in files.iter().enumerate() {
        if is_dir {
            let ok = f
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| EXTS.contains(&e.to_ascii_lowercase().as_str()))
                .unwrap_or(false);
            if !ok {
                continue;
            }
        }
        prog::set(&format!(
            "scanning {}/{total_files} files - {bins_with_rpc} with RPC",
            fi + 1
        ));
        let Ok(report) = ndr_core::analyze_path(f) else {
            continue;
        };
        if report.interfaces.is_empty() {
            continue;
        }
        ndr_fuzz::vlog!(
            "scanned {}: {} candidate interface(s)",
            f.display(),
            report.interfaces.len()
        );
        if is_dir && report.interfaces.len() < a.min {
            continue;
        }
        let grammars = ndr_core::grammars_for_report(&report);
        if grammars.is_empty() {
            continue;
        }
        bins_with_rpc += 1;
        for g in grammars {
            if g.methods.is_empty() || !seen.insert(g.interface.clone()) {
                continue;
            }
            let Some(uuid) = ndr_fuzz::dcerpc::parse_uuid(&g.interface) else {
                continue;
            };
            let (maj, min) = parse_version(&g.version);
            ifaces.push(Iface {
                uuid_str: g.interface.clone(),
                uuid,
                maj,
                min,
                source: f.clone(),
                grammar: g,
            });
        }
    }

    prog::clear();
    println!(
        "[hail-mary] {}: {bins_with_rpc} binary(ies) host RPC, {} distinct fuzzable interface(s)",
        a.path.display(),
        ifaces.len()
    );

    // Report buffer.
    let mut rep = String::new();
    rep.push_str("# NDRaider hail-mary report\n\n");
    rep.push_str(&format!(
        "- Target: `{}`\n- Binaries hosting RPC: {bins_with_rpc}\n- Distinct fuzzable interfaces: {}\n\n",
        a.path.display(),
        ifaces.len()
    ));
    rep.push_str("## Interfaces\n\n");
    for i in &ifaces {
        rep.push_str(&format!(
            "- `{}` v{}.{} - {} method(s) - `{}`\n",
            i.uuid_str,
            i.maj,
            i.min,
            i.grammar.methods.len(),
            i.source.display()
        ));
    }
    rep.push('\n');

    // 3. Offline corpus (safe; always run when --out is set).
    let mut cfg = GenConfig::default();
    if a.json {
        cfg.json_payload = true;
        cfg.json_seeds = load_json_seeds(a.seeds.as_deref());
        println!(
            "[hail-mary] JSON-over-RPC payload mode ({} seed(s))",
            cfg.json_seeds.len()
        );
    }
    if let Some(out) = &a.out {
        let cdir = out.join("corpus");
        let per = a.count.min(16);
        let mut cases = 0u64;
        for i in &ifaces {
            let uuid8 = i.uuid_str.split('-').next().unwrap_or("iface");
            for m in &i.grammar.methods {
                let mut rng = Rng::new(method_seed(a.seed, m.opnum));
                let d = cdir.join(uuid8).join(format!("op{}", m.opnum));
                std::fs::create_dir_all(&d)?;
                for n in 0..per {
                    let buf = generate_request(m, &mut rng, &cfg);
                    std::fs::write(d.join(format!("case_{n:04}.bin")), &buf)?;
                    cases += 1;
                }
            }
        }
        println!(
            "[hail-mary] wrote {cases} offline corpus case(s) under {}",
            cdir.display()
        );
        rep.push_str(&format!(
            "## Offline corpus\n\n{cases} case(s) under `{}`\n\n",
            cdir.display()
        ));
    }

    // 4. Live: discover endpoints, bind-match, fuzz.
    if a.live {
        if !a.i_am_authorized {
            bail!("--live sends real RPC traffic; pass --i-am-authorized");
        }
        println!("[hail-mary] LIVE: discovering ncalrpc endpoints and bind-matching...");
        let hits = live_hunt(&ifaces, &cfg, a.count, a.seed, a.cov, a.out.as_deref());
        rep.push_str("## Live fuzzing\n\n");
        if hits.is_empty() {
            rep.push_str("No live endpoint matched a discovered interface.\n\n");
            println!("[hail-mary] no live endpoint served any discovered interface.");
        } else {
            rep.push_str("| endpoint | interface | pid | cases | faults | disconnects | coverage | crash |\n");
            rep.push_str("|---|---|---|---|---|---|---|---|\n");
            for h in &hits {
                let covs = h
                    .cov
                    .map(|(c, t)| format!("{c}/{t}"))
                    .unwrap_or_else(|| "-".into());
                let crashs = h.crash.clone().unwrap_or_else(|| "-".into());
                rep.push_str(&format!(
                    "| `{}` | `{}` | {} | {} | {} | {} | {} | {} |\n",
                    h.endpoint,
                    &h.uuid[..8],
                    h.owner.map(|p| p.to_string()).unwrap_or_else(|| "?".into()),
                    h.cases,
                    h.faults,
                    h.disc,
                    covs,
                    crashs
                ));
            }
            rep.push('\n');

            // Full crash details (registers / backtrace / stack) for any crash.
            for h in &hits {
                if let Some(report) = &h.crash_report {
                    rep.push_str(&format!(
                        "### Crash on `{}` (pid {})\n\n```\n{report}\n```\n\n",
                        h.endpoint,
                        h.owner.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
                    ));
                }
            }
        }
    }

    // 5. Write the report.
    let out_dir = a.out.clone().unwrap_or_else(|| PathBuf::from("."));
    std::fs::create_dir_all(&out_dir)?;
    let reppath = out_dir.join("ndr-hailmary-report.md");
    std::fs::write(&reppath, rep)?;
    println!("[hail-mary] report written to {}", reppath.display());
    Ok(())
}

/// Discover live ncalrpc endpoints, bind-match the discovered interfaces, and
/// fuzz each match (optionally coverage-instrumented). Windows-only.
#[cfg(windows)]
fn live_hunt(
    ifaces: &[Iface],
    cfg: &GenConfig,
    count: u64,
    seed: u64,
    do_cov: bool,
    out: Option<&std::path::Path>,
) -> Vec<LiveHit> {
    let mut hits = Vec::new();
    let Ok(entries) = ndr_fuzz::alpc::list_object_directory(r"\RPC Control", None) else {
        return hits;
    };
    let ports = entries.iter().filter(|(_, ty)| ty == "ALPC Port").count();
    ndr_fuzz::vlog!(
        "discovered {ports} ALPC port(s); bind-matching {} interface(s)",
        ifaces.len()
    );
    let mut probed = 0usize;
    let mut matched = 0usize;
    for (name, ty) in entries {
        // Skip COM/OLE churn ports; they won't serve our NDR interfaces.
        if ty != "ALPC Port" || name.starts_with("OLE") {
            continue;
        }
        probed += 1;
        prog::set(&format!(
            "bind-matching endpoints - {probed}/{ports} probed, {matched} matched"
        ));
        ndr_fuzz::vlog!("probing endpoint {name}");
        for i in ifaces {
            // A quick bind is the match test.
            if ndr_fuzz::alpc::AlpcRpc::bind(&name, i.uuid, i.maj, i.min).is_ok() {
                matched += 1;
                prog::clear();
                ndr_fuzz::vlog!("MATCH: {name} serves {}", &i.uuid_str[..8]);
                let owner = ndr_fuzz::alpc::AlpcPort::connect(&name, &[])
                    .ok()
                    .and_then(|p| p.server_pid());
                let hit = fuzz_endpoint(i, &name, owner, cfg, count, seed, do_cov, out);
                let cs = hit
                    .cov
                    .map(|(c, t)| format!(" cov {c}/{t}"))
                    .unwrap_or_default();
                let crs = hit
                    .crash
                    .as_ref()
                    .map(|c| format!("  <-- CRASH: {c}"))
                    .unwrap_or_default();
                println!(
                    "  [LIVE] {name} <- {} v{}.{} pid {:?}: {} case(s), {} fault(s), {} disc{cs}{crs}",
                    &i.uuid_str[..8],
                    i.maj,
                    i.min,
                    owner,
                    hit.cases,
                    hit.faults,
                    hit.disc
                );
                hits.push(hit);
                break; // one interface per endpoint
            }
        }
    }
    hits
}

/// Fuzz one matched endpoint, optionally attaching a coverage debugger to the
/// server process first (so we get block coverage + precise crash detection).
#[cfg(windows)]
#[allow(clippy::too_many_arguments)]
fn fuzz_endpoint(
    iface: &Iface,
    endpoint: &str,
    owner: Option<u32>,
    cfg: &GenConfig,
    count: u64,
    seed: u64,
    do_cov: bool,
    out: Option<&std::path::Path>,
) -> LiveHit {
    use std::time::Instant;
    // Optional coverage attach (best-effort; needs matching privilege).
    let mut dbg = None;
    if do_cov {
        if let Some(pid) = owner {
            let is_dll = iface
                .source
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("dll"))
                .unwrap_or(false);
            let module = if is_dll {
                iface.source.file_name().and_then(|s| s.to_str())
            } else {
                None
            };
            ndr_fuzz::vlog!(
                "attaching coverage debugger to pid {pid} (module: {})",
                module.unwrap_or("main image")
            );
            if let Ok(d) = ndr_fuzz::cov::instrument_attach(pid, module, &iface.source) {
                let c = d.coverage().clone();
                let t0 = Instant::now();
                while !c.ready() && t0.elapsed() < Duration::from_secs(10) {
                    std::thread::sleep(Duration::from_millis(50));
                }
                if c.ready() && !c.exited() {
                    if c.wow64() {
                        ndr_fuzz::vlog!(
                            "WOW64 target: block coverage disabled (unsafe); attached for crash-detection only"
                        );
                    } else {
                        ndr_fuzz::vlog!(
                            "coverage debugger ready: {} blocks instrumented",
                            c.total()
                        );
                    }
                    dbg = Some(d);
                } else {
                    ndr_fuzz::vlog!(
                        "coverage attach didn't take (privilege / module not loaded) - fuzzing without coverage"
                    );
                }
            } else {
                ndr_fuzz::vlog!("attach failed (privilege/bitness?) - fuzzing without coverage");
            }
        }
    }

    ndr_fuzz::vlog!(
        "binding {} v{}.{} on \\RPC Control\\{endpoint}",
        &iface.uuid_str[..8],
        iface.maj,
        iface.min
    );
    // If attached with an --out dir, let the fuzz loop save the crashing input +
    // a register/stack report when the debugger catches a crash.
    let crash_out = match (&dbg, out) {
        (Some(d), Some(o)) => Some((&**d.coverage(), o, endpoint)),
        _ => None,
    };
    let (cases, faults, disc) =
        match ndr_fuzz::alpc::AlpcRpc::bind(endpoint, iface.uuid, iface.maj, iface.min) {
            Ok(rpc) => {
                fuzz_all_methods_alpc(rpc, &iface.grammar.methods, count, seed, cfg, crash_out)
            }
            Err(_) => (0, 0, 0),
        };

    let (cov, crash, crash_report) = match &dbg {
        Some(d) => {
            let c = d.coverage();
            let cr = c.take_crash();
            (
                Some((c.covered(), c.total())),
                cr.as_ref().map(|x| x.describe()),
                cr.as_ref().map(|x| x.report()),
            )
        }
        None => (None, None, None),
    };
    // dbg drops here -> clean detach (breakpoints restored).

    LiveHit {
        endpoint: endpoint.to_string(),
        uuid: iface.uuid_str.clone(),
        owner,
        cases,
        faults,
        disc,
        cov,
        crash,
        crash_report,
    }
}

#[cfg(not(windows))]
fn live_hunt(
    _i: &[Iface],
    _c: &GenConfig,
    _n: u64,
    _s: u64,
    _cov: bool,
    _out: Option<&std::path::Path>,
) -> Vec<LiveHit> {
    eprintln!("[hail-mary] live fuzzing (ncalrpc) is only available on Windows");
    Vec::new()
}

struct GenArgs {
    path: PathBuf,
    interface: usize,
    opnum: u32,
    count: u64,
    seed: u64,
    out: Option<PathBuf>,
    target: Option<String>,
    pipe: Option<String>,
    auth: bool,
    timeout_ms: u64,
    i_am_authorized: bool,
}

fn grammars(path: &PathBuf) -> Result<Vec<ndr_core::grammar::FuzzGrammar>> {
    let report =
        ndr_core::analyze_path(path).with_context(|| format!("analyzing {}", path.display()))?;
    Ok(ndr_core::grammars_for_report(&report))
}

fn list(path: PathBuf) -> Result<()> {
    let gs = grammars(&path)?;
    if gs.is_empty() {
        println!("no interfaces with decoded methods in {}", path.display());
        return Ok(());
    }
    for (i, g) in gs.iter().enumerate() {
        println!(
            "[{i}] {} v{}  ({} methods)",
            g.interface,
            g.version,
            g.methods.len()
        );
        for m in &g.methods {
            let inl = m.request.len();
            println!("      opnum {:>3}: {} request field(s)", m.opnum, inl);
        }
    }
    Ok(())
}

fn gen(a: GenArgs) -> Result<()> {
    use ndr_fuzz::Transport;

    let gs = grammars(&a.path)?;
    let g = gs
        .get(a.interface)
        .with_context(|| format!("interface index {} out of range", a.interface))?;
    let Some(method) = g.methods.iter().find(|m| m.opnum == a.opnum) else {
        bail!("opnum {} not found in interface {}", a.opnum, a.interface);
    };

    let cfg = GenConfig::default();
    let mut rng = Rng::new(a.seed);
    let opnum = a.opnum;

    eprintln!(
        "generating for {} opnum {opnum} ({} request fields), {} case(s), seed {}",
        g.interface,
        method.request.len(),
        a.count,
        a.seed,
    );

    // Live fuzzing path (TCP or local named pipe).
    if a.target.is_some() || a.pipe.is_some() {
        if !a.i_am_authorized {
            bail!(
                "refusing to send live traffic without --i-am-authorized.\n\
                 Sending malformed RPC may CRASH the target service. Only do this against \
                 systems you own or are authorized to test."
            );
        }
        let (maj, min) = parse_version(&g.version);
        let uuid = ndr_fuzz::dcerpc::parse_uuid(&g.interface)
            .with_context(|| format!("bad interface uuid {}", g.interface))?;

        let authn = if a.auth { "NTLM" } else { "none" };
        if let Some(pipe) = &a.pipe {
            eprintln!(
                "[live] binding {} v{maj}.{min} over pipe {pipe} (auth={authn})",
                g.interface
            );
            let conn = ndr_fuzz::connect_pipe(pipe, uuid, maj, min, a.auth)
                .with_context(|| format!("opening/binding pipe {pipe}"))?;
            run_live(conn, method, &mut rng, &cfg, opnum, a.count);
        } else {
            let target = a.target.as_ref().unwrap();
            eprintln!(
                "[live] binding {} v{maj}.{min} at {target} (auth={authn})",
                g.interface
            );
            let conn = ndr_fuzz::connect_tcp(
                target,
                uuid,
                maj,
                min,
                Duration::from_millis(a.timeout_ms),
                a.auth,
            )
            .with_context(|| format!("connecting/binding to {target}"))?;
            run_live(conn, method, &mut rng, &cfg, opnum, a.count);
        }
        return Ok(());
    }

    // Offline: files or hex.
    let mut sink = match &a.out {
        Some(dir) => Some(ndr_fuzz::FileSink::new(dir).context("creating output dir")?),
        None => None,
    };
    for i in 0..a.count {
        let buf = generate_request(method, &mut rng, &cfg);
        match &mut sink {
            Some(s) => s.send(opnum, i, &buf).context("writing request")?,
            None => println!("case {i:>4} ({:>4} bytes): {}", buf.len(), hex(&buf)),
        }
    }
    if let Some(dir) = a.out {
        eprintln!("wrote {} request(s) to {}", a.count, dir.display());
    }
    Ok(())
}

/// Drive a bound connection: generate + send `count` cases, report signals.
fn run_live<S: std::io::Read + std::io::Write>(
    mut conn: ndr_fuzz::RpcConn<S>,
    method: &ndr_core::grammar::MethodGrammar,
    rng: &mut Rng,
    cfg: &GenConfig,
    opnum: u32,
    count: u64,
) {
    use ndr_fuzz::Transport;
    for i in 0..count {
        let buf = generate_request(method, rng, cfg);
        if let Err(e) = conn.send(opnum, i, &buf) {
            eprintln!("[!] transport error on case {i} (possible crash): {e}");
            break;
        }
    }
    let s = conn.stats;
    eprintln!(
        "[live] done: sent={} responses={} faults={} disconnects={}",
        s.sent, s.responses, s.faults, s.disconnects
    );
}

/// Parse a grammar version string ("1.0") into (major, minor).
fn parse_version(v: &str) -> (u16, u16) {
    let mut parts = v.split('.');
    let maj = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    let min = parts.next().and_then(|s| s.parse().ok()).unwrap_or(0);
    (maj, min)
}

fn hex(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}
