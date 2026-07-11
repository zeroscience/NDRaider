//! Transport seam - how a marshaled request actually reaches a server.
//!
//! Sending an NDR request to a live RPC/DCOM endpoint is Windows-RPC-runtime
//! territory (binding via `RpcStringBindingCompose` + a low-level
//! `NdrClientCall`, or raw ALPC/named-pipe PDUs). That is the next increment;
//! it is inherently a live-target concern and is kept behind this trait so the
//! generator/marshaler above stay pure and offline-testable.
//!
//! For now we ship two safe sinks: [`FileSink`] (write each request to disk for
//! offline analysis or replay by an external client) and [`NullSink`].

use std::io::Write;
use std::path::{Path, PathBuf};

/// A destination for generated request buffers.
pub trait Transport {
    /// Deliver one request buffer for the given interface/opnum. `iteration` is
    /// the fuzz-case index. Returns whether delivery succeeded.
    fn send(&mut self, opnum: u32, iteration: u64, request: &[u8]) -> std::io::Result<()>;
}

/// Discards everything (dry runs / benchmarking the generator).
pub struct NullSink;

impl Transport for NullSink {
    fn send(&mut self, _opnum: u32, _iteration: u64, _request: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writes each request to `dir/op<opnum>_<iteration>.bin`.
pub struct FileSink {
    dir: PathBuf,
}

impl FileSink {
    pub fn new<P: AsRef<Path>>(dir: P) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(FileSink {
            dir: dir.as_ref().to_path_buf(),
        })
    }
}

impl Transport for FileSink {
    fn send(&mut self, opnum: u32, iteration: u64, request: &[u8]) -> std::io::Result<()> {
        let path = self.dir.join(format!("op{opnum}_{iteration:06}.bin"));
        let mut f = std::fs::File::create(path)?;
        f.write_all(request)?;
        Ok(())
    }
}

// NOTE (next increment): a `RpcRuntimeTransport` implementing this trait would
// bind to `ncalrpc:[endpoint]` (local ALPC) or `ncacn_ip_tcp` and issue the
// call by opnum, capturing crashes/exceptions from the server as the fuzz
// signal. Local ncalrpc is the fastest and safest first target.
