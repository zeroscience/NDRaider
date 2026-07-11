//! A DCE/RPC connection generic over any byte stream (`Read + Write`).
//!
//! The same bind/request/reply logic drives both `ncacn_ip_tcp` (a `TcpStream`)
//! and local `ncacn_np` named pipes (a `File`). Local named-pipe calls are not
//! "remote clients", so they bypass the `RestrictRemoteClients` policy that
//! faults unauthenticated TCP calls - and the pipe already carries the caller's
//! security context, so an unauthenticated bind reaches the server stub.

use crate::dcerpc;
use crate::transport::Transport;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

/// Signal accounting across a fuzz run.
#[derive(Debug, Default, Clone, Copy)]
pub struct Stats {
    pub sent: u64,
    pub responses: u64,
    pub faults: u64,
    pub disconnects: u64,
}

/// A bound DCE/RPC connection over stream `S`.
pub struct RpcConn<S: Read + Write> {
    stream: S,
    call_id: u32,
    context_id: u16,
    /// Per-PDU auth sequence number (PKT_INTEGRITY signing).
    seq_num: u32,
    /// The NTLM security context, when the connection is authenticated.
    #[cfg(windows)]
    auth: Option<crate::auth::Ntlm>,
    pub stats: Stats,
}

impl<S: Read + Write> RpcConn<S> {
    /// Bind `stream` to `(interface, NDR)`. Fails on BIND_NAK / bad reply.
    pub fn bind(
        mut stream: S,
        iface_uuid: [u8; 16],
        ver_major: u16,
        ver_minor: u16,
    ) -> io::Result<Self> {
        let bind = dcerpc::build_bind(1, iface_uuid, ver_major, ver_minor);
        stream.write_all(&bind)?;
        let reply = read_pdu(&mut stream)?;
        if std::env::var("NDR_FUZZ_DUMP").is_ok() {
            let n = reply.len().min(64);
            let hexs: String = reply[..n].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("    bind reply[..{n}]: {hexs}");
        }
        match dcerpc::parse_header(&reply).map(|h| h.pkt_type) {
            Some(dcerpc::ptype::BIND_ACK) => Ok(RpcConn {
                stream,
                call_id: 1,
                context_id: 0,
                seq_num: 0,
                #[cfg(windows)]
                auth: None,
                stats: Stats::default(),
            }),
            Some(dcerpc::ptype::BIND_NAK) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "server rejected the bind (BIND_NAK) - interface/version mismatch?",
            )),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unexpected bind reply pkt_type {other:?}"),
            )),
        }
    }
}

#[cfg(windows)]
impl<S: Read + Write> RpcConn<S> {
    /// Bind with NTLM authentication (3-leg handshake over bind / bind_ack /
    /// auth3), so calls reach the server stub. Uses the current user's creds.
    pub fn bind_auth(
        mut stream: S,
        iface_uuid: [u8; 16],
        ver_major: u16,
        ver_minor: u16,
    ) -> io::Result<Self> {
        use crate::auth::Ntlm;
        let sspi_err = |e: i32| io::Error::other(format!("SSPI error {e:#010x}"));

        let mut ntlm = Ntlm::new().map_err(sspi_err)?;
        let (tok1, _cont) = ntlm.step(None).map_err(sspi_err)?;
        if std::env::var("NDR_FUZZ_DUMP").is_ok() {
            let head: String = tok1.iter().take(12).map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "    ntlm negotiate token: {} bytes, head={head}",
                tok1.len()
            );
        }

        let level = dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY;
        // Leg 1: bind carrying the NTLM negotiate token.
        let bind = dcerpc::build_bind_auth(
            1,
            iface_uuid,
            ver_major,
            ver_minor,
            dcerpc::RPC_C_AUTHN_WINNT,
            level,
            &tok1,
        );
        stream.write_all(&bind)?;
        let ack = read_pdu(&mut stream)?;
        if std::env::var("NDR_FUZZ_DUMP").is_ok() {
            let n = ack.len().min(32);
            let hexs: String = ack[..n].iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("    auth bind reply[..{n}]: {hexs}");
        }
        match dcerpc::parse_header(&ack).map(|h| h.pkt_type) {
            Some(dcerpc::ptype::BIND_ACK) => {}
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("auth bind rejected (pkt_type {other:?})"),
                ))
            }
        }
        let challenge = dcerpc::extract_auth_token(&ack).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "bind_ack had no NTLM challenge")
        })?;

        // Leg 3: compute the authenticate token and send AUTH3.
        let (tok3, cont) = ntlm.step(Some(challenge)).map_err(sspi_err)?;
        if std::env::var("NDR_FUZZ_DUMP").is_ok() {
            let head: String = tok3.iter().take(12).map(|b| format!("{b:02x}")).collect();
            eprintln!(
                "    challenge: {} bytes; authenticate: {} bytes, continue={cont}, head={head}",
                challenge.len(),
                tok3.len()
            );
        }
        let auth3 = dcerpc::build_auth3(1, dcerpc::RPC_C_AUTHN_WINNT, level, &tok3);
        stream.write_all(&auth3)?; // no reply expected

        Ok(RpcConn {
            stream,
            call_id: 1,
            context_id: 0,
            seq_num: 0,
            auth: Some(ntlm),
            stats: Stats::default(),
        })
    }
}

/// Read one whole PDU: the 16-byte header then `frag_length - 16` more bytes.
fn read_pdu<S: Read>(stream: &mut S) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 16];
    stream.read_exact(&mut header)?;
    let h = dcerpc::parse_header(&header)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "not a v5 PDU"))?;
    let remaining = (h.frag_length as usize).saturating_sub(16);
    let mut rest = vec![0u8; remaining];
    stream.read_exact(&mut rest)?;
    let mut pdu = header.to_vec();
    pdu.extend_from_slice(&rest);
    Ok(pdu)
}

impl<S: Read + Write> RpcConn<S> {
    /// Build the REQUEST PDU - signed (PKT_INTEGRITY) when authenticated.
    fn make_request(&mut self, opnum: u32, stub: &[u8]) -> io::Result<Vec<u8>> {
        let call_id = self.call_id;
        let ctx = self.context_id;
        #[cfg(windows)]
        {
            let seq = self.seq_num;
            if let Some(auth) = self.auth.as_mut() {
                self.seq_num = seq.wrapping_add(1); // disjoint field, OK to write here
                return dcerpc::build_request_signed(
                    call_id,
                    opnum as u16,
                    ctx,
                    stub,
                    dcerpc::RPC_C_AUTHN_WINNT,
                    dcerpc::RPC_C_AUTHN_LEVEL_PKT_INTEGRITY,
                    |h, s, t| {
                        auth.sign_request(seq, h, s, t)
                            .map_err(|e| io::Error::other(format!("SSPI sign {e:#010x}")))
                    },
                );
            }
        }
        Ok(dcerpc::build_request(call_id, opnum as u16, ctx, stub))
    }
}

impl<S: Read + Write> Transport for RpcConn<S> {
    fn send(&mut self, opnum: u32, _iteration: u64, request: &[u8]) -> io::Result<()> {
        self.call_id = self.call_id.wrapping_add(1);
        self.stats.sent += 1;

        let pdu = self.make_request(opnum, request)?;

        // A write/read error (ConnectionReset/broken pipe) is the strongest fuzz
        // signal: the server very likely crashed on our input.
        if let Err(e) = self.stream.write_all(&pdu) {
            self.stats.disconnects += 1;
            return Err(e);
        }
        match read_pdu(&mut self.stream) {
            Ok(reply) => {
                match dcerpc::parse_header(&reply).map(|h| h.pkt_type) {
                    Some(dcerpc::ptype::RESPONSE) => self.stats.responses += 1,
                    Some(dcerpc::ptype::FAULT) => {
                        self.stats.faults += 1;
                        let status = dcerpc::fault_status(&reply).unwrap_or(0);
                        let pfc = reply.get(3).copied().unwrap_or(0);
                        let did_not_exec = pfc & 0x20 != 0;
                        eprintln!(
                            "[!] FAULT opnum {opnum} status {status:#010x} pfc {pfc:#04x} \
                             did_not_execute={did_not_exec}"
                        );
                        if std::env::var("NDR_FUZZ_DUMP").is_ok() {
                            let n = reply.len().min(48);
                            let hexs: String =
                                reply[..n].iter().map(|b| format!("{b:02x}")).collect();
                            eprintln!("    fault pdu[..{n}]: {hexs}");
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
            Err(e) => {
                self.stats.disconnects += 1;
                Err(e)
            }
        }
    }
}

fn tcp_stream(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    let stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    Ok(stream)
}

fn pipe_file(endpoint: &str) -> io::Result<std::fs::File> {
    let name = endpoint.trim_start_matches('\\');
    let name = name.strip_prefix("pipe\\").unwrap_or(name);
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(format!(r"\\.\pipe\{name}"))
}

/// Connect + bind over `ncacn_ip_tcp` (e.g. "127.0.0.1:49152").
pub fn connect_tcp(
    addr: &str,
    iface_uuid: [u8; 16],
    ver_major: u16,
    ver_minor: u16,
    timeout: Duration,
    auth: bool,
) -> io::Result<RpcConn<TcpStream>> {
    let stream = tcp_stream(addr, timeout)?;
    bind_stream(stream, iface_uuid, ver_major, ver_minor, auth)
}

/// Open + bind over a local `ncacn_np` named pipe. `endpoint` is the pipe path
/// the server registered, e.g. `\pipe\ndrtest` → opened as `\\.\pipe\ndrtest`.
pub fn connect_pipe(
    endpoint: &str,
    iface_uuid: [u8; 16],
    ver_major: u16,
    ver_minor: u16,
    auth: bool,
) -> io::Result<RpcConn<std::fs::File>> {
    let pipe = pipe_file(endpoint)?;
    bind_stream(pipe, iface_uuid, ver_major, ver_minor, auth)
}

#[cfg(windows)]
fn bind_stream<S: Read + Write>(
    stream: S,
    uuid: [u8; 16],
    maj: u16,
    min: u16,
    auth: bool,
) -> io::Result<RpcConn<S>> {
    if auth {
        RpcConn::bind_auth(stream, uuid, maj, min)
    } else {
        RpcConn::bind(stream, uuid, maj, min)
    }
}

#[cfg(not(windows))]
fn bind_stream<S: Read + Write>(
    stream: S,
    uuid: [u8; 16],
    maj: u16,
    min: u16,
    _auth: bool,
) -> io::Result<RpcConn<S>> {
    RpcConn::bind(stream, uuid, maj, min)
}
