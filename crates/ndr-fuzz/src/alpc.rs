//! Local ALPC / LRPC transport (`ncalrpc`) - the local RPC transport used by
//! most Windows services.
//!
//! Unlike `ncacn_ip_tcp` / `ncacn_np` (which carry the DCE/RPC PDUs directly
//! over a byte stream), `ncalrpc` uses **LRPC**: a Microsoft-proprietary,
//! undocumented message protocol over **ALPC ports**. So this module cannot
//! reuse `dcerpc.rs`; it speaks ALPC syscalls (`NtAlpcConnectPort`,
//! `NtAlpcSendWaitReceivePort`) directly and builds LRPC messages by hand.
//!
//! Layers, built + validated end-to-end against the local `NdrTestServer`
//! (which also listens on `ncalrpc:ndrtestalpc`):
//!   1. [`AlpcPort::connect`] - open the server's ALPC port
//!      (`\RPC Control\<endpoint>`) with a synchronous connection.
//!   2. [`build_bind_message`] / [`parse_bind_reply`] - negotiate the interface
//!      (DCE/NDR transfer syntax) over the connection.
//!   3. [`build_request_message`] / [`parse_response`] - carry opnum + NDR stub
//!      data and read the response or fault.
//!
//! [`AlpcRpc`] ties these together (bind + call), the ncalrpc analogue of
//! `RpcConn`. Unlike ncacn, LRPC binds implicitly under the caller's token, so
//! no explicit SSPI handshake is needed to reach handler code.
//!
//! References: [MS-RPCE] is silent on LRPC; the wire layouts here were taken
//! from James Forshaw's open-source LRPC client (NtCoreLib
//! `RpcAlpcClientTransport` + the `LRPC_*` structs) and validated on the wire.

#![cfg(windows)]
#![allow(non_snake_case, non_camel_case_types, dead_code)]

use std::io;

// --- ntdll ALPC types (undocumented; layouts from ntifs.h / reversed headers) -

#[repr(C)]
#[derive(Clone, Copy)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

/// `PORT_MESSAGE` - the ALPC message header (0x28 bytes on x64). Actual payload
/// follows immediately after.
#[repr(C)]
#[derive(Clone, Copy)]
struct PortMessage {
    data_length: u16,  // u1.s1.DataLength (payload length)
    total_length: u16, // u1.s1.TotalLength (header + payload)
    msg_type: u16,     // u2.s2.Type
    data_info_offset: u16,
    client_id_process: isize,
    client_id_thread: isize,
    message_id: u32,
    _pad: u32,
    client_view_size: usize, // union with CallbackId
}

impl Default for PortMessage {
    fn default() -> Self {
        // Safe: all-zero is a valid PORT_MESSAGE.
        unsafe { std::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Default)]
struct SecurityQos {
    length: u32,
    impersonation_level: u32,
    context_tracking_mode: u8,
    effective_only: u8,
    _pad: [u8; 2],
}

/// `ALPC_PORT_ATTRIBUTES` (x64 layout). `SecurityQos` follows `Flags` directly
/// (both 4-aligned); `MaxMessageLength` onward are 8-aligned SIZE_T.
#[repr(C)]
#[derive(Default)]
struct AlpcPortAttributes {
    flags: u32,
    security_qos: SecurityQos,
    max_message_length: usize,
    memory_bandwidth: usize,
    max_pool_usage: usize,
    max_section_size: usize,
    max_view_size: usize,
    max_total_section_size: usize,
    dup_object_types: u32,
    reserved: u32,
}

extern "system" {
    fn NtAlpcConnectPort(
        PortHandle: *mut isize,
        PortName: *const UnicodeString,
        ObjectAttributes: *const core::ffi::c_void,
        PortAttributes: *const AlpcPortAttributes,
        Flags: u32,
        RequiredServerSid: *const core::ffi::c_void,
        ConnectionMessage: *mut PortMessage,
        BufferLength: *mut usize,
        OutMessageAttributes: *mut core::ffi::c_void,
        InMessageAttributes: *mut core::ffi::c_void,
        Timeout: *const i64,
    ) -> i32;

    fn NtAlpcSendWaitReceivePort(
        PortHandle: isize,
        Flags: u32,
        SendMessage: *const PortMessage,
        SendMessageAttributes: *mut core::ffi::c_void,
        ReceiveMessage: *mut PortMessage,
        BufferLength: *mut usize,
        ReceiveMessageAttributes: *mut core::ffi::c_void,
        Timeout: *const i64,
    ) -> i32;

    fn NtClose(Handle: isize) -> i32;

    fn NtOpenDirectoryObject(
        DirectoryHandle: *mut isize,
        DesiredAccess: u32,
        ObjectAttributes: *const ObjectAttributes,
    ) -> i32;

    fn NtQueryDirectoryObject(
        DirectoryHandle: isize,
        Buffer: *mut u8,
        Length: u32,
        ReturnSingleEntry: u8,
        RestartScan: u8,
        Context: *mut u32,
        ReturnLength: *mut u32,
    ) -> i32;

    fn NtAlpcQueryInformation(
        PortHandle: isize,
        PortInformationClass: u32,
        PortInformation: *mut core::ffi::c_void,
        Length: u32,
        ReturnLength: *mut u32,
    ) -> i32;
}

/// `AlpcServerSessionInformation` - query class returning the server's
/// `{ SessionId, ProcessId }` for a connected client port.
const ALPC_SERVER_SESSION_INFORMATION: u32 = 12;

/// `OBJECT_ATTRIBUTES` (x64, 48 bytes).
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    _pad0: u32,
    root_directory: isize,
    object_name: *const UnicodeString,
    attributes: u32,
    _pad1: u32,
    security_descriptor: *const core::ffi::c_void,
    security_qos: *const core::ffi::c_void,
}

/// `OBJECT_DIRECTORY_INFORMATION` (x64): two UNICODE_STRINGs (Name, TypeName).
#[repr(C)]
#[derive(Clone, Copy)]
struct ObjectDirectoryInformation {
    name: UnicodeString,
    type_name: UnicodeString,
}

const DIRECTORY_QUERY: u32 = 0x0001;
const STATUS_MORE_ENTRIES: i32 = 0x0000_0105;
const STATUS_NO_MORE_ENTRIES: i32 = 0x8000_001A_u32 as i32;

const STATUS_SUCCESS: i32 = 0;
/// `ALPC_MSGFLG_SYNC_REQUEST` - synchronous request/reply. Passed both as the
/// connection flags (so the connect establishes a synchronous connection - a
/// connect *without* this leaves the port in a state that rejects
/// `NtAlpcSendWaitReceivePort` with STATUS_LPC_INVALID_CONNECTION_USAGE) and on
/// every subsequent send. Value confirmed against NtCoreLib `AlpcMessageFlags`.
const ALPC_MSGFLG_SYNC_REQUEST: u32 = 0x2_0000;

// `AlpcPortAttributeFlags` (from NtCoreLib) - the exact set the Windows RPC
// runtime uses for an LRPC client port.
const ALPC_PORFLG_ALLOW_IMPERSONATION: u32 = 0x1_0000;
const ALPC_PORFLG_WAITABLE_PORT: u32 = 0x4_0000;
const ALPC_PORFLG_ALLOW_DUP_OBJECT: u32 = 0x8_0000;
const ALPC_PORFLG_ALLOW_MULTI_HANDLE_ATTR: u32 = 0x200_0000;
/// `AlpcHandleObjectType.AllObjects` (File|Thread|Semaphore|Event|Process|Mutex|
/// Section|RegKey|Token|Composition|Job).
const ALPC_HANDLE_ALL_OBJECTS: u32 = 0xFFD;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().collect()
}

/// A connected ALPC port handle. LRPC bind/request will be layered on top.
pub struct AlpcPort {
    handle: isize,
}

impl AlpcPort {
    /// Open the server ALPC port for an `ncalrpc` endpoint. `connect_payload`
    /// is the data sent with the connection request (the LRPC bind, once we
    /// build it; empty for a bare reachability probe).
    ///
    /// Returns the raw NTSTATUS in the error so callers can distinguish
    /// "port not found" from "connection refused" etc.
    pub fn connect(endpoint: &str, connect_payload: &[u8]) -> Result<AlpcPort, i32> {
        let port_path = format!(r"\RPC Control\{endpoint}");
        let name_utf16 = wide(&port_path);
        let byte_len = (name_utf16.len() * 2) as u16;
        let uname = UnicodeString {
            length: byte_len,
            maximum_length: byte_len,
            buffer: name_utf16.as_ptr() as *mut u16,
        };

        // Port attributes matching the Windows RPC runtime's LRPC client (see
        // NtCoreLib RpcAlpcClientTransport.CreatePortAttributes): the flag set,
        // MaxMessageLength 0x1000, and the Max* section limits set to -1.
        let mut attrs = AlpcPortAttributes {
            flags: ALPC_PORFLG_ALLOW_IMPERSONATION
                | ALPC_PORFLG_WAITABLE_PORT
                | ALPC_PORFLG_ALLOW_DUP_OBJECT
                | ALPC_PORFLG_ALLOW_MULTI_HANDLE_ATTR,
            max_message_length: 0x1000,
            memory_bandwidth: 0,
            max_pool_usage: usize::MAX,
            max_section_size: usize::MAX,
            max_view_size: usize::MAX,
            max_total_section_size: usize::MAX,
            dup_object_types: ALPC_HANDLE_ALL_OBJECTS,
            ..Default::default()
        };
        attrs.security_qos.length = std::mem::size_of::<SecurityQos>() as u32;
        attrs.security_qos.impersonation_level = 2; // SecurityImpersonation

        // Connection message: PORT_MESSAGE header + optional payload, in one
        // buffer. BufferLength is in/out.
        let header = std::mem::size_of::<PortMessage>();
        let mut buf = vec![0u8; header + connect_payload.len().max(0x400)];
        {
            let msg = buf.as_mut_ptr() as *mut PortMessage;
            unsafe {
                (*msg).data_length = connect_payload.len() as u16;
                (*msg).total_length = (header + connect_payload.len()) as u16;
            }
            if !connect_payload.is_empty() {
                buf[header..header + connect_payload.len()].copy_from_slice(connect_payload);
            }
        }
        let mut buf_len: usize = buf.len();

        // Establish a *synchronous* connection: ALPC_MSGFLG_SYNC_REQUEST must be
        // passed as the connection flags, otherwise later
        // NtAlpcSendWaitReceivePort calls fail with
        // STATUS_LPC_INVALID_CONNECTION_USAGE (0xc0000707). null Timeout = wait
        // forever. (Confirmed against NtCoreLib RpcAlpcClientTransport, which
        // passes AlpcMessageFlags.SyncRequest as the connect flags.)
        let mut handle: isize = 0;
        let status = unsafe {
            NtAlpcConnectPort(
                &mut handle,
                &uname,
                std::ptr::null(),
                &attrs,
                ALPC_MSGFLG_SYNC_REQUEST,
                std::ptr::null(),
                buf.as_mut_ptr() as *mut PortMessage,
                &mut buf_len,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if status == STATUS_SUCCESS {
            Ok(AlpcPort { handle })
        } else {
            Err(status)
        }
    }
}

impl AlpcPort {
    /// Send an LRPC message payload as a synchronous ALPC request and return the
    /// reply payload (the bytes after the reply's PORT_MESSAGE header).
    ///
    /// `payload` is the LRPC message body (starting with the LRPC message type,
    /// per the SyScan/Ionescu protocol notes) that follows the PORT_MESSAGE.
    pub fn send_receive(&self, payload: &[u8]) -> Result<Vec<u8>, i32> {
        let header = std::mem::size_of::<PortMessage>();

        // Send buffer: PORT_MESSAGE + payload.
        let mut send = vec![0u8; header + payload.len()];
        {
            let msg = send.as_mut_ptr() as *mut PortMessage;
            unsafe {
                (*msg).data_length = payload.len() as u16;
                (*msg).total_length = (header + payload.len()) as u16;
            }
            send[header..].copy_from_slice(payload);
        }

        // Receive buffer sized for a max ALPC message (64 KB).
        let mut recv = vec![0u8; 0x10000];
        let mut recv_len: usize = recv.len();

        // SYNC_REQUEST: send this message and block for the paired reply. Works
        // once the connection was itself established with SYNC_REQUEST (see
        // `connect`); otherwise this returns STATUS_LPC_INVALID_CONNECTION_USAGE.
        let status = unsafe {
            NtAlpcSendWaitReceivePort(
                self.handle,
                ALPC_MSGFLG_SYNC_REQUEST,
                send.as_ptr() as *const PortMessage,
                std::ptr::null_mut(),
                recv.as_mut_ptr() as *mut PortMessage,
                &mut recv_len,
                std::ptr::null_mut(),
                std::ptr::null(),
            )
        };
        if status != STATUS_SUCCESS {
            return Err(status);
        }
        // Return the reply payload (after the PORT_MESSAGE header).
        let reply = recv.as_ptr() as *const PortMessage;
        let data_len = unsafe { (*reply).data_length } as usize;
        let end = (header + data_len).min(recv.len());
        Ok(recv[header..end].to_vec())
    }
}

impl AlpcPort {
    /// The PID of the process serving this ALPC port (i.e. the RPC server to
    /// attach a debugger to). Uses `NtAlpcQueryInformation`.
    pub fn server_pid(&self) -> Option<u32> {
        // ALPC_SERVER_SESSION_INFORMATION { u32 SessionId; u32 ProcessId; }.
        let mut buf = [0u32; 2];
        let mut ret: u32 = 0;
        let st = unsafe {
            NtAlpcQueryInformation(
                self.handle,
                ALPC_SERVER_SESSION_INFORMATION,
                buf.as_mut_ptr() as *mut core::ffi::c_void,
                (buf.len() * 4) as u32,
                &mut ret,
            )
        };
        if st == STATUS_SUCCESS && buf[1] != 0 {
            Some(buf[1])
        } else {
            None
        }
    }
}

impl Drop for AlpcPort {
    fn drop(&mut self) {
        if self.handle != 0 {
            unsafe {
                NtClose(self.handle);
            }
        }
    }
}

/// LRPC message types (`LRPC_MESSAGE_TYPE`, from NtCoreLib / reversed runtime).
pub mod lrpc_msg {
    pub const REQUEST: u32 = 0;
    pub const BIND: u32 = 1;
    pub const FAULT: u32 = 2;
    pub const RESPONSE: u32 = 3;
    pub const CANCEL: u32 = 4;
}

/// `TransferSyntaxSetFlags`.
const TSS_USE_DCE: u32 = 1;

/// Parsed result of an LRPC bind reply.
pub struct BindResult {
    /// Windows error/RPC status the server returned (0 = success).
    pub rpc_status: u32,
    /// The negotiated binding id used in the `BindingId` field of requests.
    pub binding_id: i16,
}

/// Build the exact 72-byte `LRPC_BIND_MESSAGE` a DCE/NDR LRPC client sends.
///
/// Layout (x64, StructLayout.Sequential, natural alignment) - byte offsets:
/// ```text
///  0  LRPC_HEADER.MessageType (u32) = lmtBind(1)
///  4  LRPC_HEADER.Padding     (u32) = 0
///  8  RpcStatus               (u32) = 0
/// 12  Interface: RPC_SYNTAX_IDENTIFIER {
/// 12    SyntaxGUID  (16 bytes, wire form)
/// 28    MajorVersion (u16), 30 MinorVersion (u16)  }
/// 32  TransferSyntaxSet (u32) = UseDce(1)
/// 36  DceNdrSyntaxIdentifier   (i16)
/// 38  Ndr64SyntaxIdentifier    (i16)
/// 40  FakeNdr64SyntaxIdentifier(i16)
/// 42  (pad 2)
/// 44  RegisterMultipleSyntax (BOOL u32) = 0
/// 48  UseFlowId              (BOOL u32) = 0
/// 52  (pad 4)
/// 56  FlowId    (i64) = 0
/// 64  ContextId (u32) = 0
/// 68  (tail pad 4)  -> total 72
/// ```
pub fn build_bind_message(iface_uuid: [u8; 16], ver_major: u16, ver_minor: u16) -> Vec<u8> {
    let mut p = vec![0u8; 72];
    p[0..4].copy_from_slice(&lrpc_msg::BIND.to_le_bytes());
    // RpcStatus (8) stays 0.
    p[12..28].copy_from_slice(&iface_uuid);
    p[28..30].copy_from_slice(&ver_major.to_le_bytes());
    p[30..32].copy_from_slice(&ver_minor.to_le_bytes());
    p[32..36].copy_from_slice(&TSS_USE_DCE.to_le_bytes());
    p
}

/// Parse an LRPC bind reply payload (an echoed `LRPC_BIND_MESSAGE`). Returns the
/// server's RpcStatus and the negotiated DCE binding id.
pub fn parse_bind_reply(reply: &[u8]) -> Result<BindResult, String> {
    // A FAULT reply (e.g. RPC_S_UNKNOWN_IF 0x6b5 = wrong interface for this port)
    // is short (~20 bytes), so classify by message type before the length check.
    if reply.len() >= 12 {
        let msg_type = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
        if msg_type == lrpc_msg::FAULT {
            let status = u32::from_le_bytes([reply[8], reply[9], reply[10], reply[11]]);
            return Err(format!("server returned LRPC fault, RpcStatus {status:#x}"));
        }
    }
    if reply.len() < 38 {
        return Err(format!("bind reply too short ({} bytes)", reply.len()));
    }
    let msg_type = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
    if msg_type != lrpc_msg::BIND {
        return Err(format!("unexpected LRPC reply message type {msg_type}"));
    }
    let rpc_status = u32::from_le_bytes([reply[8], reply[9], reply[10], reply[11]]);
    // DceNdrSyntaxIdentifier lives at offset 36 (i16).
    let binding_id = i16::from_le_bytes([reply[36], reply[37]]);
    Ok(BindResult {
        rpc_status,
        binding_id,
    })
}

/// Build an `LRPC_IMMEDIATE_REQUEST_MESSAGE` (64-byte header) followed by the
/// marshalled NDR stub data. Used for stub buffers up to ~0xF00 bytes; larger
/// requests use a data-view section (not yet implemented).
///
/// Header layout (x64) - byte offsets:
/// ```text
///  0  LRPC_HEADER.MessageType (u32) = lmtRequest(0)
///  4  LRPC_HEADER.Padding     (u32) = 0
///  8  Flags     (u32)   (0, or ObjectUuid=1 when an object UUID is present)
/// 12  CallId    (u32)
/// 16  BindingId (u32)   (negotiated at bind)
/// 20  ProcNum   (u32)   (opnum)
/// 24  Unk18 .. 44 Unk2C (six u32, 0)
/// 48  ObjectUuid (16 bytes, present only if the ObjectUuid flag is set)
/// ```
pub fn build_request_message(binding_id: i16, call_id: u32, proc_num: u32, stub: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 64];
    // MessageType lmtRequest = 0 (already zero).
    p[12..16].copy_from_slice(&call_id.to_le_bytes());
    p[16..20].copy_from_slice(&(binding_id as u32).to_le_bytes());
    p[20..24].copy_from_slice(&proc_num.to_le_bytes());
    // ObjectUuid (offset 48) left zero; no ObjectUuid flag.
    p.extend_from_slice(stub);
    p
}

/// Parse an `LRPC_IMMEDIATE_RESPONSE_MESSAGE`: returns the NDR response stub
/// (the bytes after the 24-byte response header), or the fault status.
pub fn parse_response(reply: &[u8]) -> Result<Vec<u8>, String> {
    if reply.len() < 12 {
        return Err(format!("response too short ({} bytes)", reply.len()));
    }
    let msg_type = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
    if msg_type == lrpc_msg::FAULT {
        let status = u32::from_le_bytes([reply[8], reply[9], reply[10], reply[11]]);
        return Err(format!("LRPC fault, RpcStatus {status:#x}"));
    }
    if msg_type != lrpc_msg::RESPONSE {
        return Err(format!("unexpected LRPC response message type {msg_type}"));
    }
    // Immediate response: NDR data follows the 24-byte header.
    let body = if reply.len() > 24 { &reply[24..] } else { &[] };
    Ok(body.to_vec())
}

/// Map an NTSTATUS to a readable io::Error for the CLI.
pub fn nt_error(status: i32) -> io::Error {
    io::Error::other(format!("NTSTATUS {status:#010x}"))
}

fn read_unicode(u: &UnicodeString) -> String {
    if u.buffer.is_null() || u.length == 0 {
        return String::new();
    }
    let n = (u.length / 2) as usize;
    let slice = unsafe { std::slice::from_raw_parts(u.buffer, n) };
    String::from_utf16_lossy(slice)
}

/// Enumerate a kernel object directory (e.g. `\RPC Control`) and return
/// `(name, type_name)` for each entry, optionally filtered by a case-insensitive
/// substring of the name. Used to discover live ncalrpc/ALPC port names without
/// guessing. Returns the raw NTSTATUS on failure to open the directory.
pub fn list_object_directory(
    dir_path: &str,
    filter: Option<&str>,
) -> Result<Vec<(String, String)>, i32> {
    let name_utf16 = wide(dir_path);
    let byte_len = (name_utf16.len() * 2) as u16;
    let uname = UnicodeString {
        length: byte_len,
        maximum_length: byte_len,
        buffer: name_utf16.as_ptr() as *mut u16,
    };
    let oa = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        _pad0: 0,
        root_directory: 0,
        object_name: &uname,
        attributes: 0,
        _pad1: 0,
        security_descriptor: std::ptr::null(),
        security_qos: std::ptr::null(),
    };

    let mut dir: isize = 0;
    let st = unsafe { NtOpenDirectoryObject(&mut dir, DIRECTORY_QUERY, &oa) };
    if st != STATUS_SUCCESS {
        return Err(st);
    }

    let mut out = Vec::new();
    let mut buf = vec![0u8; 0x10000];
    let mut context: u32 = 0;
    let entry_size = std::mem::size_of::<ObjectDirectoryInformation>();
    let mut first = true;
    // Cap iterations defensively; \RPC Control fits in a couple of 64 KB passes.
    for _ in 0..256 {
        let mut ret_len: u32 = 0;
        let st = unsafe {
            NtQueryDirectoryObject(
                dir,
                buf.as_mut_ptr(),
                buf.len() as u32,
                0, // ReturnSingleEntry = FALSE
                first as u8,
                &mut context,
                &mut ret_len,
            )
        };
        first = false;
        if st != STATUS_SUCCESS && st != STATUS_MORE_ENTRIES {
            break; // STATUS_NO_MORE_ENTRIES or a real error
        }
        let mut i = 0usize;
        loop {
            let p =
                unsafe { buf.as_ptr().add(i * entry_size) as *const ObjectDirectoryInformation };
            let e = unsafe { *p };
            if e.name.length == 0 && e.name.buffer.is_null() {
                break; // zeroed terminator entry
            }
            let name = read_unicode(&e.name);
            let ty = read_unicode(&e.type_name);
            let keep = filter
                .map(|f| name.to_lowercase().contains(&f.to_lowercase()))
                .unwrap_or(true);
            if keep {
                out.push((name, ty));
            }
            i += 1;
        }
        if st != STATUS_MORE_ENTRIES {
            break;
        }
    }
    unsafe {
        NtClose(dir);
    }
    Ok(out)
}

/// Outcome of one LRPC call.
pub enum CallOutcome {
    /// The server ran the handler and returned an NDR response buffer.
    Response(Vec<u8>),
    /// The server's RPC runtime rejected the request (e.g. NDR unmarshal error).
    /// This is the *normal* signal that a structure-aware mutation was caught -
    /// it is not a crash. Carries the RpcStatus.
    Fault(u32),
    /// The generated stub was too large for an inline (immediate) LRPC message
    /// and we don't implement ALPC data-view sections yet, so the case was not
    /// sent. Not a fault and not a crash - just skipped.
    Skipped,
}

/// Max stub size we send inline. LRPC switches to a data-view section above
/// ~0xF00 bytes; we only do immediate messages, so cases bigger than this are
/// skipped rather than sent (a failed oversized send would look like a crash).
const LRPC_IMMEDIATE_MAX_STUB: usize = 0xE00;

/// A bound LRPC connection: an ALPC port plus the negotiated binding id and a
/// per-connection call-id counter. This is the ncalrpc analogue of `RpcConn`.
pub struct AlpcRpc {
    port: AlpcPort,
    binding_id: i16,
    call_id: u32,
}

impl AlpcRpc {
    /// Connect to `endpoint` and bind `iface_uuid` v`maj`.`min` over DCE/NDR.
    /// Errors carry a human-readable reason (bad connect NTSTATUS, LRPC fault,
    /// or a non-zero RpcStatus from the bind).
    pub fn bind(
        endpoint: &str,
        iface_uuid: [u8; 16],
        maj: u16,
        min: u16,
    ) -> Result<AlpcRpc, String> {
        let port = AlpcPort::connect(endpoint, &[])
            .map_err(|s| format!("connect failed NTSTATUS {s:#010x}"))?;
        let msg = build_bind_message(iface_uuid, maj, min);
        let reply = port
            .send_receive(&msg)
            .map_err(|s| format!("bind send failed NTSTATUS {s:#010x}"))?;
        let r = parse_bind_reply(&reply)?;
        if r.rpc_status != 0 {
            return Err(format!("bind refused, RpcStatus {:#x}", r.rpc_status));
        }
        Ok(AlpcRpc {
            port,
            binding_id: r.binding_id,
            // Windows RPC uses call ids starting at 1.
            call_id: 1,
        })
    }

    /// Invoke `opnum` with a marshalled NDR `stub`. `Ok` distinguishes a handler
    /// response from an RPC fault; `Err(NTSTATUS)` means the ALPC send itself
    /// failed - the connection is dead, which for a fuzzer is a possible crash.
    pub fn call(&mut self, opnum: u32, stub: &[u8]) -> Result<CallOutcome, i32> {
        if stub.len() > LRPC_IMMEDIATE_MAX_STUB {
            crate::vlog!(
                "opnum {opnum}: {}-byte stub too big for an immediate LRPC message - skipped",
                stub.len()
            );
            return Ok(CallOutcome::Skipped);
        }
        crate::vlog!(
            "-> opnum {opnum} call#{}: send {} bytes {}",
            self.call_id,
            stub.len(),
            crate::hex_prefix(stub, 24)
        );
        let msg = build_request_message(self.binding_id, self.call_id, opnum, stub);
        self.call_id = self.call_id.wrapping_add(1);
        let reply = match self.port.send_receive(&msg) {
            Ok(r) => r,
            Err(s) => {
                crate::vlog!(
                    "<- opnum {opnum}: ALPC send failed NTSTATUS {s:#010x} (server gone?)"
                );
                return Err(s);
            }
        };
        if reply.len() >= 12 {
            let ty = u32::from_le_bytes([reply[0], reply[1], reply[2], reply[3]]);
            if ty == lrpc_msg::FAULT {
                let status = u32::from_le_bytes([reply[8], reply[9], reply[10], reply[11]]);
                crate::vlog!("<- opnum {opnum}: FAULT RpcStatus {status:#x}");
                return Ok(CallOutcome::Fault(status));
            }
        }
        match parse_response(&reply) {
            Ok(body) => {
                crate::vlog!("<- opnum {opnum}: response {} byte(s)", body.len());
                Ok(CallOutcome::Response(body))
            }
            // A malformed/short reply we couldn't classify: treat as an empty
            // response rather than a transport death.
            Err(_) => Ok(CallOutcome::Response(Vec::new())),
        }
    }
}
