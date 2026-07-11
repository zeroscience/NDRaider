//! A minimal Windows debugger that collects **basic-block coverage** and
//! **catches crashes** in a target, by either spawning it or attaching to a
//! running process.
//!
//! Technique (the classic "breakpoint coverage, one-shot" approach):
//!   * Spawn with `DEBUG_ONLY_THIS_PROCESS`, or `DebugActiveProcess(pid)` to
//!     attach - the OS then delivers debug events on this thread.
//!   * When the instrumented module loads (the main image, or a named DLL matched
//!     via its file handle), write `0xCC` at every basic-block leader.
//!   * On each breakpoint, mark the block covered, **restore** the original byte,
//!     and rewind `RIP` - so each block traps at most once and overhead decays.
//!   * A fatal exception (second-chance, or a non-continuable /GS / heap fault)
//!     is recorded as a crash with the faulting instruction and address. Benign
//!     first-chance RPC faults the runtime handles are ignored.
//!
//! On **attach**, we restore every not-yet-hit breakpoint before detaching, so a
//! service we don't own is left exactly as we found it. On **spawn**, the child
//! is terminated on drop.
//!
//! The debug loop runs on its own thread; the fuzzer reads the shared
//! [`Coverage`] while sending RPC. Scope: x64 target/host.
#![allow(non_snake_case)]

use ndr_core::pe::PeImage;
use std::collections::HashMap;
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, DebugActiveProcess, DebugActiveProcessStop, FlushInstructionCache,
    GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent,
    Wow64GetThreadContext, Wow64SetThreadContext, WriteProcessMemory, CONTEXT, DEBUG_EVENT,
    EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, WOW64_CONTEXT,
};
use windows_sys::Win32::System::Memory::{VirtualProtectEx, PAGE_EXECUTE_READWRITE};
use windows_sys::Win32::System::Threading::{
    CreateProcessW, IsWow64Process, OpenThread, TerminateProcess, PROCESS_INFORMATION, STARTUPINFOW,
};

const DEBUG_ONLY_THIS_PROCESS: u32 = 0x0000_0002;
const CREATE_PROCESS_DEBUG_EVENT_CODE: u32 = 3;
const LOAD_DLL_DEBUG_EVENT_CODE: u32 = 6;
// ContinueDebugEvent's continue status is an NTSTATUS (i32).
const DBG_CONTINUE: i32 = 0x0001_0002;
const DBG_EXCEPTION_NOT_HANDLED: i32 = 0x8001_0001_u32 as i32;
const EXCEPTION_BREAKPOINT: u32 = 0x8000_0003;
const STATUS_WX86_BREAKPOINT: u32 = 0x4000_001F;
const THREAD_GET_CONTEXT: u32 = 0x0008;
const THREAD_SET_CONTEXT: u32 = 0x0010;
const CONTEXT_CONTROL_AMD64: u32 = 0x0010_0001;
const CONTEXT_INTEGER_AMD64: u32 = 0x0010_0002;
// WOW64_CONTEXT_i386 (0x00010000) | CONTROL (0x1) - for 32-bit targets.
const WOW64_CONTEXT_CONTROL: u32 = 0x0001_0001;
const WOW64_CONTEXT_INTEGER: u32 = 0x0001_0002;
const ERROR_SEM_TIMEOUT: u32 = 121;
const WAIT_TIMEOUT: u32 = 258;

/// How to obtain the target process.
enum Start {
    Spawn(Vec<u16>),
    Attach(u32),
}

/// Details of a caught crash in the target, including register + stack context.
#[derive(Clone, Debug, Default)]
pub struct CrashInfo {
    /// The exception/NTSTATUS code (e.g. 0xC0000005 access violation).
    pub code: u32,
    /// Faulting instruction address (RIP/EIP).
    pub rip: u64,
    /// For access violations: 0 = read, 1 = write, 8 = execute.
    pub access_type: u64,
    /// For access violations: the inaccessible data address.
    pub access_addr: u64,
    /// True if the faulting thread was 32-bit (WOW64).
    pub wow64: bool,
    /// Runtime base of the instrumented module (for RVA-izing addresses).
    pub module_base: u64,
    /// Named registers at the fault.
    pub regs: Vec<(&'static str, u64)>,
    /// Raw stack words from the stack pointer upward.
    pub stack: Vec<u64>,
    /// Stack words that point into the instrumented module's code (a naive
    /// backtrace: candidate return addresses).
    pub frames: Vec<u64>,
}

impl CrashInfo {
    pub fn describe(&self) -> String {
        let kind = match self.code {
            0xC000_0005 => {
                let op = match self.access_type {
                    0 => "read",
                    1 => "write",
                    8 => "execute",
                    _ => "access",
                };
                format!("ACCESS_VIOLATION ({op} @ {:#018x})", self.access_addr)
            }
            0xC000_001D => "ILLEGAL_INSTRUCTION".into(),
            0xC000_0094 => "INTEGER_DIVIDE_BY_ZERO".into(),
            0xC000_00FD => "STACK_OVERFLOW".into(),
            0xC000_0374 => "HEAP_CORRUPTION".into(),
            0xC000_0409 => "STACK_BUFFER_OVERRUN (/GS)".into(),
            other => format!("exception {other:#010x}"),
        };
        format!("{kind} at RIP {:#018x}", self.rip)
    }

    /// Address relative to the instrumented module (`module+0xRVA`) if it falls
    /// within a sensible range, else the raw address.
    fn as_modrva(&self, addr: u64) -> String {
        if self.module_base != 0
            && addr >= self.module_base
            && addr < self.module_base + 0x1000_0000
        {
            format!("{addr:#018x} (module+{:#x})", addr - self.module_base)
        } else {
            format!("{addr:#018x}")
        }
    }

    /// A full human-readable crash report: exception, registers, backtrace, stack.
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str("=== NDRaider crash report ===\n");
        s.push_str(&format!("exception : {}\n", self.describe()));
        s.push_str(&format!("faulting  : {}\n", self.as_modrva(self.rip)));
        if self.code == 0xC000_0005 {
            let op = match self.access_type {
                0 => "read",
                1 => "write",
                8 => "execute",
                _ => "access",
            };
            s.push_str(&format!("access    : {op} of {:#018x}\n", self.access_addr));
        }
        s.push_str(&format!(
            "arch      : {}\n\n",
            if self.wow64 { "x86 (WOW64)" } else { "x64" }
        ));

        s.push_str("registers:\n");
        for (name, val) in &self.regs {
            let width = if self.wow64 { 8 } else { 16 };
            s.push_str(&format!("  {name:<4} {val:#0w$x}\n", w = width + 2));
        }
        s.push('\n');

        s.push_str("backtrace (stack words pointing into the instrumented module):\n");
        if self.frames.is_empty() {
            s.push_str("  (none - fault likely outside the instrumented module)\n");
        } else {
            for (i, f) in self.frames.iter().enumerate() {
                s.push_str(&format!("  #{i} {}\n", self.as_modrva(*f)));
            }
        }
        s.push('\n');

        s.push_str("stack dump (from SP up):\n");
        for (i, w) in self.stack.iter().enumerate() {
            let mark = if self.module_base != 0
                && *w >= self.module_base
                && *w < self.module_base + 0x1000_0000
            {
                "  <- module"
            } else {
                ""
            };
            let width = if self.wow64 { 8 } else { 16 };
            s.push_str(&format!(
                "  +{:#05x}  {w:#0width$x}{mark}\n",
                i * if self.wow64 { 4 } else { 8 },
                width = width + 2
            ));
        }
        s
    }
}

/// Shared coverage + crash state between the debug thread and the fuzzer.
pub struct Coverage {
    total: usize,
    covered_count: AtomicUsize,
    covered: Vec<AtomicBool>,
    ready: AtomicBool,
    exited: AtomicBool,
    stop: AtomicBool,
    wow64: AtomicBool,
    crash: Mutex<Option<CrashInfo>>,
    proc_handle: AtomicIsize,
}

impl Coverage {
    pub fn total(&self) -> usize {
        self.total
    }
    pub fn covered(&self) -> usize {
        self.covered_count.load(Ordering::Relaxed)
    }
    pub fn ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }
    pub fn exited(&self) -> bool {
        self.exited.load(Ordering::Acquire)
    }
    /// True if the target is a 32-bit (WOW64) process. Block-coverage
    /// instrumentation is disabled for these (it corrupts the target); the
    /// debugger stays attached passively for real crash detection only.
    pub fn wow64(&self) -> bool {
        self.wow64.load(Ordering::Acquire)
    }
    pub fn take_crash(&self) -> Option<CrashInfo> {
        self.crash.lock().unwrap().take()
    }
    /// Clone the recorded crash without consuming it.
    pub fn peek_crash(&self) -> Option<CrashInfo> {
        self.crash.lock().unwrap().clone()
    }
    pub fn has_crash(&self) -> bool {
        self.crash.lock().unwrap().is_some()
    }
}

/// A spawned or attached, instrumented target.
pub struct Debuggee {
    cov: Arc<Coverage>,
    thread: Option<JoinHandle<()>>,
    kill_on_drop: bool,
}

impl Debuggee {
    pub fn coverage(&self) -> &Arc<Coverage> {
        &self.cov
    }

    /// Spawn `exe` under the debugger. `module` = `None` instruments the main
    /// image; `Some(dll_name)` instruments that DLL once it loads.
    pub fn spawn(
        exe: &std::path::Path,
        module: Option<String>,
        block_rvas: Vec<u32>,
        code_regions: Vec<(u32, u32)>,
    ) -> std::io::Result<Debuggee> {
        let exe_wide: Vec<u16> = exe
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        Self::start(
            Start::Spawn(exe_wide),
            module,
            block_rvas,
            code_regions,
            true,
        )
    }

    /// Attach to an already-running process `pid`. `module` names the DLL to
    /// instrument (or `None` for the main image). On drop we detach cleanly,
    /// restoring any breakpoints not yet hit - the process keeps running.
    pub fn attach(
        pid: u32,
        module: Option<String>,
        block_rvas: Vec<u32>,
        code_regions: Vec<(u32, u32)>,
    ) -> std::io::Result<Debuggee> {
        Self::start(Start::Attach(pid), module, block_rvas, code_regions, false)
    }

    fn start(
        start: Start,
        module: Option<String>,
        block_rvas: Vec<u32>,
        code_regions: Vec<(u32, u32)>,
        kill_on_drop: bool,
    ) -> std::io::Result<Debuggee> {
        let total = block_rvas.len();
        let mut covered = Vec::with_capacity(total);
        covered.resize_with(total, || AtomicBool::new(false));
        let cov = Arc::new(Coverage {
            total,
            covered_count: AtomicUsize::new(0),
            covered,
            ready: AtomicBool::new(false),
            exited: AtomicBool::new(false),
            stop: AtomicBool::new(false),
            wow64: AtomicBool::new(false),
            crash: Mutex::new(None),
            proc_handle: AtomicIsize::new(0),
        });
        let cov_thread = cov.clone();
        let module_lc = module.map(|m| m.to_lowercase());
        let thread = std::thread::Builder::new()
            .name("ndr-cov-debugger".into())
            .spawn(move || debug_loop(start, module_lc, block_rvas, code_regions, cov_thread))?;
        Ok(Debuggee {
            cov,
            thread: Some(thread),
            kill_on_drop,
        })
    }
}

impl Drop for Debuggee {
    fn drop(&mut self) {
        // Ask the debug loop to stop (it polls this flag). For a spawned child we
        // also terminate it; for an attached process the loop detaches cleanly.
        self.cov.stop.store(true, Ordering::Release);
        if self.kill_on_drop {
            let h = self.cov.proc_handle.load(Ordering::Acquire);
            if h != 0 {
                unsafe {
                    TerminateProcess(h as _, 0);
                }
            }
        }
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

/// Compute the `.text` `(rva, size)` regions of a PE (for page-protection).
pub fn code_regions(pe: &PeImage) -> Vec<(u32, u32)> {
    pe.section_slices()
        .filter(|(s, _)| s.name == ".text" || s.name.starts_with(".text") || s.name == "CODE")
        .map(|(s, _)| (s.virtual_address, s.virtual_size))
        .collect()
}

fn debug_loop(
    start: Start,
    module_lc: Option<String>,
    block_rvas: Vec<u32>,
    code_regions: Vec<(u32, u32)>,
    cov: Arc<Coverage>,
) {
    unsafe {
        let attach_pid = match &start {
            Start::Attach(pid) => Some(*pid),
            Start::Spawn(_) => None,
        };
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let started = match &start {
            Start::Spawn(exe_wide) => {
                let mut si: STARTUPINFOW = std::mem::zeroed();
                si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
                CreateProcessW(
                    exe_wide.as_ptr(),
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                    0,
                    DEBUG_ONLY_THIS_PROCESS,
                    std::ptr::null(),
                    std::ptr::null(),
                    &si,
                    &mut pi,
                ) != 0
            }
            Start::Attach(pid) => DebugActiveProcess(*pid) != 0,
        };
        if !started {
            crate::vlog!("debugger: failed to start/attach to the target");
            cov.exited.store(true, Ordering::Release);
            cov.ready.store(true, Ordering::Release);
            return;
        }
        match attach_pid {
            Some(pid) => crate::vlog!("debugger: attached to pid {pid}"),
            None => crate::vlog!("debugger: spawned target under a debug loop"),
        }

        let mut idx_of: HashMap<u32, usize> = HashMap::with_capacity(block_rvas.len());
        for (i, r) in block_rvas.iter().enumerate() {
            idx_of.insert(*r, i);
        }
        let mut orig: Vec<u8> = vec![0; block_rvas.len()];
        let mut h_proc: HANDLE = std::ptr::null_mut();
        let mut base: u64 = 0;
        let mut installed = false;
        let mut is_wow64 = false;

        let mut ev: DEBUG_EVENT = std::mem::zeroed();
        'evt: loop {
            if WaitForDebugEvent(&mut ev, 100) == 0 {
                let e = GetLastError();
                if e == ERROR_SEM_TIMEOUT || e == WAIT_TIMEOUT {
                    if cov.stop.load(Ordering::Acquire) {
                        break 'evt;
                    }
                    continue;
                }
                break 'evt; // a real error
            }
            let mut status = DBG_CONTINUE;
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT_CODE => {
                    let info = ev.u.CreateProcessInfo;
                    h_proc = info.hProcess;
                    cov.proc_handle.store(h_proc as isize, Ordering::Release);
                    // 32-bit (WOW64) targets need the Wow64 register context.
                    let mut wow: i32 = 0;
                    if IsWow64Process(h_proc, &mut wow) != 0 {
                        is_wow64 = wow != 0;
                    }
                    cov.wow64.store(is_wow64, Ordering::Release);
                    crate::vlog!(
                        "debugger: process created, image base {:#x}, wow64={is_wow64}",
                        info.lpBaseOfImage as u64
                    );
                    if module_lc.is_none() {
                        base = info.lpBaseOfImage as u64;
                        // Block instrumentation of WOW64 targets is disabled: it
                        // corrupts the 32-bit thread on the emulation boundary and
                        // crashes the process. Stay attached passively (real crash
                        // detection still works, just no coverage).
                        if is_wow64 {
                            crate::vlog!("debugger: WOW64 target - coverage DISABLED (passive crash-detect only)");
                        } else {
                            install_breakpoints(
                                h_proc,
                                base,
                                &block_rvas,
                                &code_regions,
                                &mut orig,
                            );
                            installed = true;
                            crate::vlog!(
                                "debugger: instrumented {} basic blocks in the main image",
                                block_rvas.len()
                            );
                        }
                        cov.ready.store(true, Ordering::Release);
                    }
                    if !info.hFile.is_null() && info.hFile != INVALID_HANDLE_VALUE {
                        CloseHandle(info.hFile);
                    }
                }
                LOAD_DLL_DEBUG_EVENT_CODE => {
                    let info = ev.u.LoadDll;
                    if !installed {
                        if let Some(want) = &module_lc {
                            if dll_name_matches(info.hFile, want) {
                                base = info.lpBaseOfDll as u64;
                                if is_wow64 {
                                    crate::vlog!(
                                        "debugger: matched module {want} at base {base:#x} (WOW64) - coverage DISABLED (passive crash-detect only)"
                                    );
                                } else {
                                    install_breakpoints(
                                        h_proc,
                                        base,
                                        &block_rvas,
                                        &code_regions,
                                        &mut orig,
                                    );
                                    installed = true;
                                    crate::vlog!(
                                        "debugger: matched module {want} at base {base:#x}; instrumented {} basic blocks",
                                        block_rvas.len()
                                    );
                                }
                                cov.ready.store(true, Ordering::Release);
                            }
                        }
                    }
                    if !info.hFile.is_null() && info.hFile != INVALID_HANDLE_VALUE {
                        CloseHandle(info.hFile);
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let er = ev.u.Exception.ExceptionRecord;
                    let code = er.ExceptionCode as u32;
                    let addr = er.ExceptionAddress as u64;
                    if (code == EXCEPTION_BREAKPOINT || code == STATUS_WX86_BREAKPOINT)
                        && installed
                        && base != 0
                    {
                        let rva = addr.wrapping_sub(base) as u32;
                        if let Some(&i) = idx_of.get(&rva) {
                            if !cov.covered[i].swap(true, Ordering::Relaxed) {
                                cov.covered_count.fetch_add(1, Ordering::Relaxed);
                            }
                            write_mem(h_proc, addr, &[orig[i]]);
                            FlushInstructionCache(h_proc, addr as *const c_void, 1);
                            rewind_rip(ev.dwThreadId, addr, is_wow64);
                        }
                    } else if code != EXCEPTION_BREAKPOINT && code != STATUS_WX86_BREAKPOINT {
                        let first_chance = ev.u.Exception.dwFirstChance != 0;
                        if std::env::var_os("NDR_COV_DEBUG").is_some() {
                            eprintln!(
                                "[cov-dbg] exception {code:#010x} first_chance={} rip={addr:#018x}",
                                first_chance as u8
                            );
                        }
                        if is_fatal(code) && (!first_chance || is_noncontinuable(code)) {
                            let (regs, stack, frames) = capture_context(
                                ev.dwThreadId,
                                is_wow64,
                                h_proc,
                                &code_regions,
                                base,
                            );
                            let ci = CrashInfo {
                                code,
                                rip: addr,
                                access_type: er.ExceptionInformation[0] as u64,
                                access_addr: er.ExceptionInformation[1] as u64,
                                wow64: is_wow64,
                                module_base: base,
                                regs,
                                stack,
                                frames,
                            };
                            let mut slot = cov.crash.lock().unwrap();
                            if slot.is_none() {
                                crate::vlog!("debugger: caught {}", ci.describe());
                                *slot = Some(ci);
                            }
                        }
                        status = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    cov.exited.store(true, Ordering::Release);
                    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    break 'evt;
                }
                _ => {}
            }
            ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status);
            if cov.stop.load(Ordering::Acquire) {
                break 'evt;
            }
        }

        // Detach cleanly when attached: restore breakpoints we never hit so the
        // process (which we don't own) is left byte-for-byte as we found it.
        if let Some(pid) = attach_pid {
            if installed && !cov.exited.load(Ordering::Acquire) && !h_proc.is_null() {
                let mut restored = 0usize;
                for (i, rva) in block_rvas.iter().enumerate() {
                    if !cov.covered[i].load(Ordering::Relaxed) {
                        write_mem(h_proc, base + *rva as u64, &[orig[i]]);
                        restored += 1;
                    }
                }
                if let Some((rva, size)) = code_regions.first() {
                    FlushInstructionCache(
                        h_proc,
                        (base + *rva as u64) as *const c_void,
                        *size as usize,
                    );
                }
                crate::vlog!(
                    "debugger: detaching from pid {pid}, restored {restored} un-hit breakpoint(s)"
                );
            }
            DebugActiveProcessStop(pid);
        }

        cov.ready.store(true, Ordering::Release);
        if attach_pid.is_none() {
            cov.exited.store(true, Ordering::Release);
        }
        if !pi.hThread.is_null() {
            CloseHandle(pi.hThread);
        }
    }
}

/// Does the DLL behind `hfile` end with the wanted (lowercased) module name?
unsafe fn dll_name_matches(hfile: HANDLE, want_lc: &str) -> bool {
    if hfile.is_null() || hfile == INVALID_HANDLE_VALUE {
        return false;
    }
    let mut buf = [0u16; 512];
    let n = GetFinalPathNameByHandleW(hfile, buf.as_mut_ptr(), buf.len() as u32, 0);
    if n == 0 || (n as usize) >= buf.len() {
        return false;
    }
    let path = String::from_utf16_lossy(&buf[..n as usize]).to_lowercase();
    let base = path.rsplit(['\\', '/']).next().unwrap_or(&path);
    base == want_lc
}

unsafe fn install_breakpoints(
    h_proc: HANDLE,
    base: u64,
    block_rvas: &[u32],
    code_regions: &[(u32, u32)],
    orig: &mut [u8],
) {
    for (rva, size) in code_regions {
        let mut old = 0u32;
        VirtualProtectEx(
            h_proc,
            (base + *rva as u64) as *const c_void,
            *size as usize,
            PAGE_EXECUTE_READWRITE,
            &mut old,
        );
    }
    for (i, rva) in block_rvas.iter().enumerate() {
        let va = base + *rva as u64;
        let mut b = [0u8; 1];
        let mut read = 0usize;
        if ReadProcessMemory(
            h_proc,
            va as *const c_void,
            b.as_mut_ptr() as *mut c_void,
            1,
            &mut read,
        ) != 0
            && read == 1
        {
            orig[i] = b[0];
            write_mem(h_proc, va, &[0xCC]);
        } else {
            orig[i] = 0xCC;
        }
    }
    if let Some((rva, size)) = code_regions.first() {
        FlushInstructionCache(
            h_proc,
            (base + *rva as u64) as *const c_void,
            *size as usize,
        );
    }
}

unsafe fn write_mem(h_proc: HANDLE, va: u64, bytes: &[u8]) {
    let mut wrote = 0usize;
    WriteProcessMemory(
        h_proc,
        va as *const c_void,
        bytes.as_ptr() as *const c_void,
        bytes.len(),
        &mut wrote,
    );
}

unsafe fn rewind_rip(thread_id: u32, addr: u64, is_wow64: bool) {
    let h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 0, thread_id);
    if h.is_null() {
        return;
    }
    if is_wow64 {
        // 32-bit target: rewind EIP via the WOW64 context.
        let mut ctx: WOW64_CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = WOW64_CONTEXT_CONTROL;
        if Wow64GetThreadContext(h, &mut ctx) != 0 {
            ctx.Eip = addr as u32;
            Wow64SetThreadContext(h, &ctx);
        }
    } else {
        let mut ctx: CONTEXT = std::mem::zeroed();
        ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
        if GetThreadContext(h, &mut ctx) != 0 {
            ctx.Rip = addr;
            SetThreadContext(h, &ctx);
        }
    }
    CloseHandle(h);
}

/// Snapshot the faulting thread's registers + a slice of its stack, and pick out
/// stack words that point into the instrumented module (a naive backtrace).
unsafe fn capture_context(
    thread_id: u32,
    wow64: bool,
    h_proc: HANDLE,
    code_regions: &[(u32, u32)],
    base: u64,
) -> (Vec<(&'static str, u64)>, Vec<u64>, Vec<u64>) {
    let mut regs: Vec<(&'static str, u64)> = Vec::new();
    let mut sp: u64 = 0;
    let h = OpenThread(THREAD_GET_CONTEXT, 0, thread_id);
    if !h.is_null() {
        if wow64 {
            let mut c: WOW64_CONTEXT = std::mem::zeroed();
            c.ContextFlags = WOW64_CONTEXT_CONTROL | WOW64_CONTEXT_INTEGER;
            if Wow64GetThreadContext(h, &mut c) != 0 {
                regs = vec![
                    ("eip", c.Eip as u64),
                    ("esp", c.Esp as u64),
                    ("ebp", c.Ebp as u64),
                    ("eax", c.Eax as u64),
                    ("ecx", c.Ecx as u64),
                    ("edx", c.Edx as u64),
                    ("ebx", c.Ebx as u64),
                    ("esi", c.Esi as u64),
                    ("edi", c.Edi as u64),
                ];
                sp = c.Esp as u64;
            }
        } else {
            let mut c: CONTEXT = std::mem::zeroed();
            c.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
            if GetThreadContext(h, &mut c) != 0 {
                regs = vec![
                    ("rip", c.Rip),
                    ("rsp", c.Rsp),
                    ("rbp", c.Rbp),
                    ("rax", c.Rax),
                    ("rcx", c.Rcx),
                    ("rdx", c.Rdx),
                    ("rbx", c.Rbx),
                    ("rsi", c.Rsi),
                    ("rdi", c.Rdi),
                    ("r8", c.R8),
                    ("r9", c.R9),
                    ("r10", c.R10),
                    ("r11", c.R11),
                    ("r12", c.R12),
                    ("r13", c.R13),
                    ("r14", c.R14),
                    ("r15", c.R15),
                ];
                sp = c.Rsp;
            }
        }
        CloseHandle(h);
    }

    let word = if wow64 { 4usize } else { 8 };
    let mut stack = Vec::new();
    let mut frames = Vec::new();
    if sp != 0 {
        let mut buf = vec![0u8; 64 * word];
        let mut read = 0usize;
        if ReadProcessMemory(
            h_proc,
            sp as *const c_void,
            buf.as_mut_ptr() as *mut c_void,
            buf.len(),
            &mut read,
        ) != 0
        {
            for i in 0..(read / word) {
                let v = if wow64 {
                    u32::from_le_bytes(buf[i * 4..i * 4 + 4].try_into().unwrap()) as u64
                } else {
                    u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap())
                };
                stack.push(v);
                if in_module(base, code_regions, v) {
                    frames.push(v);
                }
            }
        }
    }
    (regs, stack, frames)
}

fn in_module(base: u64, regions: &[(u32, u32)], addr: u64) -> bool {
    regions.iter().any(|(rva, size)| {
        let s = base + *rva as u64;
        addr >= s && addr < s + *size as u64
    })
}

/// Codes that terminate the process even on first chance (they bypass SEH /
/// the RPC runtime's `__except`), so recording them first-chance is safe.
fn is_noncontinuable(code: u32) -> bool {
    matches!(
        code,
        0xC000_0409 // STACK_BUFFER_OVERRUN (/GS __fastfail)
            | 0xC000_0374 // HEAP_CORRUPTION
            | 0xC000_001D // ILLEGAL_INSTRUCTION
            | 0xC000_00FD // STACK_OVERFLOW
            | 0xC000_0602 // FAIL_FAST_EXCEPTION
    )
}

fn is_fatal(code: u32) -> bool {
    matches!(
        code,
        0xC000_0005 // ACCESS_VIOLATION
            | 0xC000_001D // ILLEGAL_INSTRUCTION
            | 0xC000_0094 // INTEGER_DIVIDE_BY_ZERO
            | 0xC000_00FD // STACK_OVERFLOW
            | 0xC000_0374 // HEAP_CORRUPTION
            | 0xC000_0409 // STACK_BUFFER_OVERRUN (/GS)
            | 0xC000_0026 // INVALID_DISPOSITION
    )
}
