//! # ndr-fuzz
//!
//! Structure-aware DCOM/RPC request generator + mutator, driven by the fuzzing
//! grammar that `ndr-core` extracts. Pipeline:
//!
//! ```text
//! ndr-core grammar  --->  Generator (value.rs)  --->  Marshaler (marshal.rs)
//!                          structure-aware              NDR wire bytes
//!                          mutation                          |
//!                                                            v
//!                                                     Transport (transport.rs)
//! ```
//!
//! The generator and marshaler are pure and offline-testable; the transport
//! (delivering to a live endpoint) is a trait with file/null sinks today and a
//! real RPC-runtime backend as the next increment.

#[cfg(windows)]
pub mod alpc;
pub mod auth;
pub mod conn;
#[cfg(windows)]
pub mod cov;
pub mod dcerpc;
pub mod json;
pub mod marshal;
pub mod mutate;
pub mod rng;
pub mod transport;
pub mod value;

pub use conn::{connect_pipe, connect_tcp, RpcConn, Stats};
pub use marshal::{marshal, Marshaler};
pub use rng::Rng;
pub use transport::{FileSink, NullSink, Transport};
pub use value::{GenConfig, GenField, Generator, Value};

use ndr_core::grammar::MethodGrammar;
use std::sync::atomic::{AtomicBool, Ordering};

/// Global verbose switch: when on, the fuzzer and debugger narrate what they do
/// (attaching, instrumenting, each request sent, etc.) to stderr.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable/disable verbose narration (set once from the CLI `--verbose` flag).
pub fn set_verbose(on: bool) {
    VERBOSE.store(on, Ordering::Relaxed);
}

/// Whether verbose narration is on.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Print a verbose narration line (to stderr) only when `--verbose` is set.
#[macro_export]
macro_rules! vlog {
    ($($arg:tt)*) => {
        if $crate::verbose() { eprintln!("[v] {}", format!($($arg)*)); }
    };
}

/// Hex-encode a short prefix of a buffer for verbose "what we sent" lines.
pub fn hex_prefix(bytes: &[u8], max: usize) -> String {
    let n = bytes.len().min(max);
    let mut s: String = bytes[..n].iter().map(|b| format!("{b:02x}")).collect();
    if bytes.len() > n {
        s.push_str("...");
    }
    s
}

/// Generate and marshal a single fuzz case (request buffer) for a method.
pub fn generate_request(method: &MethodGrammar, rng: &mut Rng, cfg: &GenConfig) -> Vec<u8> {
    let mut gen = Generator::new(rng, cfg);
    let fields = gen.request(method);
    let values: Vec<Value> = fields.into_iter().map(|f| f.value).collect();
    marshal(&values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ndr_core::grammar::{Field, LengthSource, MethodGrammar, Node};

    /// A `count` + `[size_is(count)] long[]` method. With 100% consistency the
    /// marshaled count field must equal the array's max_count.
    fn size_is_method() -> MethodGrammar {
        MethodGrammar {
            opnum: 0,
            handler_rva: None,
            response: vec![],
            request: vec![
                Field {
                    stack_offset: 8,
                    dir: "in",
                    simple_ref: false,
                    node: Node::Int {
                        bytes: 4,
                        signed: true,
                    },
                },
                Field {
                    stack_offset: 16,
                    dir: "in",
                    simple_ref: false,
                    node: Node::Array {
                        element: Box::new(Node::Int {
                            bytes: 4,
                            signed: true,
                        }),
                        length: LengthSource::Param { stack_offset: 8 },
                        varying: false,
                    },
                },
            ],
        }
    }

    #[test]
    fn size_is_count_is_reconciled() {
        let cfg = GenConfig {
            keep_length_consistent_pct: 100,
            oversize_pct: 0,
            ..GenConfig::default()
        };
        for seed in 0..50 {
            let mut rng = Rng::new(seed);
            let buf = generate_request(&size_is_method(), &mut rng, &cfg);
            // Layout: count(u32) then array max_count(u32) then elements.
            let count = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let max_count = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
            assert_eq!(
                count, max_count,
                "count must match array length at seed {seed}"
            );
            // And the buffer must hold exactly `count` marshaled longs.
            assert_eq!(buf.len(), 8 + count as usize * 4);
        }
    }

    #[test]
    fn deterministic_from_seed() {
        let cfg = GenConfig::default();
        let a = generate_request(&size_is_method(), &mut Rng::new(7), &cfg);
        let b = generate_request(&size_is_method(), &mut Rng::new(7), &cfg);
        assert_eq!(a, b, "same seed must produce identical output");
    }
}
