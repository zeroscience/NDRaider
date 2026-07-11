//! Concrete NDR values and the structure-aware generator that produces them
//! from an [`ndr_core::grammar`] method description.
//!
//! The interesting part is *cross-field* awareness: when an array's length is
//! sourced from another parameter (`size_is(count)`), the generator can keep the
//! count field consistent with the array (to reach deep code) or deliberately
//! desynchronize it (to hunt allocation/overflow bugs) - controlled by
//! [`GenConfig::keep_length_consistent_pct`].

use crate::rng::Rng;
use ndr_core::grammar::{LengthSource, MethodGrammar, Node};

/// A concrete value ready to be marshaled into an NDR buffer.
#[derive(Debug, Clone)]
pub enum Value {
    /// An integer/float of `bytes` width; `data` holds the little-endian bits.
    Scalar { bytes: u8, data: u64 },
    /// Opaque bytes marshaled verbatim (context handles, blobs, …).
    Blob(Vec<u8>),
    /// A unique/full pointer: `None` = null (referent id 0).
    UniquePtr(Option<Box<Value>>),
    /// A reference pointer: pointee marshaled inline, no referent id.
    RefPtr(Box<Value>),
    /// A conformant (optionally varying) array.
    Array {
        max_count: u32,
        varying: bool,
        offset: u32,
        actual: u32,
        elements: Vec<Value>,
    },
    /// A fixed-size array (no count on the wire).
    FixedArray(Vec<Value>),
    /// A conformant string: `unit_size` bytes per char, `count` units incl NUL.
    ConfStr {
        unit_size: u8,
        count: u32,
        bytes: Vec<u8>,
    },
    /// A struct - members in order.
    Struct(Vec<Value>),
    /// A discriminated union: the tag then the selected arm (if any).
    Union {
        tag_bytes: u8,
        tag: u64,
        arm: Option<Box<Value>>,
    },
}

/// Knobs controlling how aggressively the generator mutates.
#[derive(Debug, Clone)]
pub struct GenConfig {
    pub max_array_len: u32,
    /// % chance a `size_is` count field is kept consistent with its array.
    pub keep_length_consistent_pct: u32,
    /// % chance a nullable pointer is generated as NULL.
    pub null_pointer_pct: u32,
    /// % chance an oversized array length is chosen (overflow bait).
    pub oversize_pct: u32,
    /// A live context handle (20 bytes) to substitute for context-handle params
    /// instead of a null handle. Set by the stateful fuzzer after calling an
    /// "opener" method, so handle-gated methods pass the runtime's handle check
    /// and reach real handler code. `None` = marshal a null handle.
    pub context_handle: Option<Vec<u8>>,
    /// JSON-payload mode: fill conformant `byte[]` buffers with a fuzzed JSON
    /// document instead of random bytes (for JSON-over-RPC services). Reaches the
    /// command handlers instead of bouncing off the JSON parser.
    pub json_payload: bool,
    /// Optional parsed JSON seed corpus to mutate (from `--seeds`); empty =
    /// synthesize.
    pub json_seeds: std::sync::Arc<Vec<serde_json::Value>>,
    /// Fill `byte[]` buffers and `char` strings with dictionary-seeded,
    /// radamsa-style havoc content (tokens + interesting bytes + byte mutation)
    /// instead of plain random/printable bytes. Reaches handler logic harder.
    pub havoc: bool,
}

impl Default for GenConfig {
    fn default() -> Self {
        GenConfig {
            // Big enough to cross the 64/128/256 allocation boundaries where
            // overflows live, small enough that a few buffers still fit the
            // ncalrpc immediate-message envelope (~0xF00 bytes) without needing
            // an ALPC data-view section.
            max_array_len: 256,
            keep_length_consistent_pct: 70,
            null_pointer_pct: 20,
            oversize_pct: 10,
            context_handle: None,
            json_payload: false,
            json_seeds: std::sync::Arc::new(Vec::new()),
            havoc: true,
        }
    }
}

/// A pending "set this count param to this length" reconciliation.
struct LenLink {
    target_stack_offset: u16,
    chosen_len: u32,
}

/// One generated request parameter.
pub struct GenField {
    pub stack_offset: u16,
    pub value: Value,
}

pub struct Generator<'a> {
    rng: &'a mut Rng,
    cfg: &'a GenConfig,
    links: Vec<LenLink>,
}

impl<'a> Generator<'a> {
    pub fn new(rng: &'a mut Rng, cfg: &'a GenConfig) -> Self {
        Generator {
            rng,
            cfg,
            links: Vec::new(),
        }
    }

    /// Generate all request fields for a method, then reconcile length links.
    pub fn request(&mut self, method: &MethodGrammar) -> Vec<GenField> {
        let mut fields: Vec<GenField> = method
            .request
            .iter()
            .map(|f| GenField {
                stack_offset: f.stack_offset,
                value: self.node(&f.node),
            })
            .collect();

        // Reconcile size_is links: with configured probability, set the count
        // parameter to match the array length; otherwise leave it desynced.
        let links = std::mem::take(&mut self.links);
        for link in links {
            let keep = self.rng.chance(self.cfg.keep_length_consistent_pct, 100);
            if !keep {
                continue;
            }
            if let Some(f) = fields
                .iter_mut()
                .find(|f| f.stack_offset == link.target_stack_offset)
            {
                set_scalar(&mut f.value, link.chosen_len as u64);
            }
        }
        fields
    }

    fn node(&mut self, node: &Node) -> Value {
        match node {
            Node::Int { bytes, signed } => Value::Scalar {
                bytes: *bytes,
                data: self.interesting_int(*bytes, *signed),
            },
            Node::Float { bytes } => Value::Scalar {
                bytes: *bytes,
                data: self.rng.next_u64(),
            },
            Node::Range { bytes, min, max } => Value::Scalar {
                bytes: *bytes,
                data: self.range_int(*bytes, *min, *max),
            },
            Node::Pointer { nullable, pointee } => {
                if *nullable && self.rng.chance(self.cfg.null_pointer_pct, 100) {
                    Value::UniquePtr(None)
                } else {
                    let inner = Box::new(self.node(pointee));
                    if *nullable {
                        Value::UniquePtr(Some(inner))
                    } else {
                        Value::RefPtr(inner)
                    }
                }
            }
            Node::Struct { fields, .. } => {
                Value::Struct(fields.iter().map(|f| self.node(f)).collect())
            }
            Node::Array {
                element, length, ..
            } => self.array(element, length),
            Node::FixedArray {
                element,
                total_bytes,
            } => {
                let esz = wire_size(element).max(1) as u32;
                let count = (*total_bytes / esz).max(1);
                let elems = (0..count).map(|_| self.node(element)).collect();
                Value::FixedArray(elems)
            }
            Node::Str { wide } => self.string(*wide),
            Node::InterfacePtr { .. } => Value::UniquePtr(None), // NULL interface ptr
            Node::ContextHandle => {
                // Use a captured live handle when the stateful fuzzer supplied
                // one; otherwise a null (all-zero) 20-byte context handle.
                let mut h = self
                    .cfg
                    .context_handle
                    .clone()
                    .unwrap_or_else(|| vec![0u8; 20]);
                h.resize(20, 0);
                Value::Blob(h)
            }
            Node::Union {
                tag_bytes, arms, ..
            } => {
                if arms.is_empty() {
                    Value::Union {
                        tag_bytes: *tag_bytes,
                        tag: self.rng.next_u64(),
                        arm: None,
                    }
                } else {
                    let i = self.rng.pick(arms.len());
                    let arm = &arms[i];
                    Value::Union {
                        tag_bytes: *tag_bytes,
                        tag: arm.case as u64,
                        arm: Some(Box::new(self.node(&arm.node))),
                    }
                }
            }
            Node::UserMarshal { wire } => self.node(wire),
            Node::Blob { .. } => {
                let n = 4 + self.rng.below(12) as usize;
                Value::Blob((0..n).map(|_| self.rng.next_u32() as u8).collect())
            }
        }
    }

    fn array(&mut self, element: &Node, length: &LengthSource) -> Value {
        // JSON-over-RPC mode: fill a conformant byte buffer with a fuzzed JSON
        // document, and set its size_is length to match so it unmarshals and
        // reaches the command handler.
        if self.cfg.json_payload && is_byte(element) {
            let jb = crate::json::json_bytes(self.rng, &self.cfg.json_seeds);
            let len = jb.len() as u32;
            let elements = jb
                .iter()
                .map(|b| Value::Scalar {
                    bytes: 1,
                    data: *b as u64,
                })
                .collect();
            if let LengthSource::Param { stack_offset } = length {
                self.links.push(LenLink {
                    target_stack_offset: *stack_offset,
                    chosen_len: len,
                });
            }
            return Value::Array {
                max_count: len,
                varying: false,
                offset: 0,
                actual: len,
                elements,
            };
        }
        // Choose a length: usually a realistic, allocation-boundary-biased size,
        // occasionally a huge max_count (NDR desync / overflow bait).
        let len = if self.rng.chance(self.cfg.oversize_pct, 100) {
            0xFFFF_u32.wrapping_sub(self.rng.below(4))
        } else {
            self.pick_boundary_len()
        };
        // Cap materialized elements at max_array_len: for a boundary length this
        // sends the whole buffer (so it survives unmarshal and the handler
        // actually processes N bytes); for an oversized max_count it caps the
        // work - the mismatch itself is the bug.
        let materialize = len.min(self.cfg.max_array_len);
        let elements = if self.cfg.havoc && is_byte(element) && materialize > 0 {
            // Dictionary-seeded havoc content for byte buffers, clamped to the
            // exact element count so all the size_is framing stays valid.
            let mut buf = crate::mutate::content(self.rng, materialize as usize);
            buf.resize(materialize as usize, 0);
            buf.into_iter()
                .map(|byte| Value::Scalar {
                    bytes: 1,
                    data: byte as u64,
                })
                .collect()
        } else {
            (0..materialize).map(|_| self.node(element)).collect()
        };

        if let LengthSource::Param { stack_offset } = length {
            self.links.push(LenLink {
                target_stack_offset: *stack_offset,
                chosen_len: len,
            });
        }
        Value::Array {
            max_count: len,
            varying: false,
            offset: 0,
            actual: len,
            elements,
        }
    }

    /// Pick an array/buffer length biased toward allocation boundaries (where
    /// off-by-one and rounding overflows live), clamped to `max_array_len`.
    fn pick_boundary_len(&mut self) -> u32 {
        // Sizes clustered around common heap/stack buffer boundaries and the
        // values just around them (N-1 / N / N+1).
        const BOUNDS: &[u32] = &[
            0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 100, 127, 128, 129, 200, 255, 256, 257,
            260, 511, 512, 513, 1000, 1023, 1024,
        ];
        if self.rng.chance(65, 100) {
            BOUNDS[self.rng.pick(BOUNDS.len())].min(self.cfg.max_array_len)
        } else {
            self.rng.below(self.cfg.max_array_len + 1)
        }
    }

    fn string(&mut self, wide: bool) -> Value {
        let unit_size = if wide { 2 } else { 1 };
        // Boundary-biased length (chars, excluding NUL) so we stress path/name
        // buffers (MAX_PATH 260, 256, 512, ...) not just tiny strings.
        let chars = self.pick_boundary_len();
        let mut bytes = Vec::new();
        if !wide && self.cfg.havoc {
            // char* strings carry the classic injection surface (paths, format
            // strings): seed them from the dictionary + havoc, exact length.
            let mut buf = crate::mutate::content(self.rng, chars as usize);
            buf.resize(chars as usize, b'A');
            bytes = buf;
        } else {
            for _ in 0..chars {
                let c = (0x20 + self.rng.below(0x5e)) as u16; // printable-ish
                if wide {
                    bytes.extend_from_slice(&c.to_le_bytes());
                } else {
                    bytes.push(c as u8);
                }
            }
        }
        // NUL terminator.
        bytes.resize(bytes.len() + unit_size as usize, 0);
        let count = chars + 1;
        Value::ConfStr {
            unit_size,
            count,
            bytes,
        }
    }

    /// Pick a boundary-biased integer for a `bytes`-wide field.
    fn interesting_int(&mut self, bytes: u8, _signed: bool) -> u64 {
        let width_mask = mask(bytes);
        let choice = self.rng.below(8);
        let v = match choice {
            0 => 0,
            1 => 1,
            2 => width_mask,            // all-ones / -1 / MAX
            3 => width_mask >> 1,       // signed MAX
            4 => (width_mask >> 1) + 1, // signed MIN
            5 => 0x8000_0000_0000_0000, // high bit
            _ => self.rng.next_u64(),   // random
        };
        v & width_mask
    }

    fn range_int(&mut self, bytes: u8, min: i64, max: i64) -> u64 {
        // Bias toward the bounds and just outside them.
        let choice = self.rng.below(6);
        let v: i64 = match choice {
            0 => min,
            1 => max,
            2 => min.wrapping_sub(1),
            3 => max.wrapping_add(1),
            4 if max > min => min + (self.rng.below((max - min) as u32) as i64),
            _ => self.rng.next_u64() as i64,
        };
        (v as u64) & mask(bytes)
    }
}

/// A single-byte integer element (the element type of a `byte[]`/`char[]`).
fn is_byte(node: &Node) -> bool {
    matches!(node, Node::Int { bytes: 1, .. })
}

fn mask(bytes: u8) -> u64 {
    match bytes {
        0 => 0,
        n if n >= 8 => u64::MAX,
        n => (1u64 << (n as u32 * 8)) - 1,
    }
}

/// Overwrite a scalar value's data (used to reconcile count params).
fn set_scalar(v: &mut Value, data: u64) {
    if let Value::Scalar { bytes, data: d } = v {
        *d = data & mask(*bytes);
    }
}

/// Wire size in bytes of a node, for fixed-array element counting.
fn wire_size(node: &Node) -> u8 {
    match node {
        Node::Int { bytes, .. } | Node::Float { bytes } | Node::Range { bytes, .. } => *bytes,
        Node::Pointer { .. } | Node::InterfacePtr { .. } => 4, // referent id
        _ => 1,
    }
}
