//! Fuzzing-grammar emitter (milestone **M4**).
//!
//! Transforms the decoded [`crate::ndr::Procedure`] model into a normalized,
//! fuzzer-oriented description of each method's **request** (the `[in]` /
//! `[in,out]` parameters that travel on the wire). A separate harness consumes
//! this grammar to marshal NDR request buffers and mutate them - structure-aware
//! fuzzing rather than blind bit-flipping.
//!
//! Design intent:
//! * Only request-direction fields are emitted as the fuzz surface (`[out]`
//!   params are captured separately for response parsing / coverage).
//! * Conformant array lengths are resolved to a [`LengthSource`] so the harness
//!   can either keep length fields consistent (to reach deep code paths) or
//!   deliberately desynchronize them (to find allocation/overflow bugs).
//! * Anything the interpreter left `Unresolved` becomes an opaque [`Node::Blob`]
//!   - still fuzzable, just without structure.
//!
//! This is the bridge artifact; it does not itself marshal or send requests.

use crate::ndr::opcodes::{self, *};
use crate::ndr::{Correlation, ParamDir, Procedure, TypeRef};
use crate::types::Version;
use serde::Serialize;

/// A complete fuzzing grammar for one RPC interface.
#[derive(Debug, Serialize)]
pub struct FuzzGrammar {
    pub interface: String,
    pub version: String,
    /// NDR marshaling reminders for the harness (not exhaustive).
    pub ndr_notes: &'static str,
    pub methods: Vec<MethodGrammar>,
}

/// Per-method grammar.
#[derive(Debug, Serialize)]
pub struct MethodGrammar {
    /// Method number = the RPC opnum used to dispatch the call.
    pub opnum: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handler_rva: Option<u32>,
    /// Fields to marshal into the request, in stack order.
    pub request: Vec<Field>,
    /// Output fields (response shape), for parsing / coverage - not fuzzed.
    pub response: Vec<Field>,
}

/// One parameter as a fuzzable field.
#[derive(Debug, Serialize)]
pub struct Field {
    pub stack_offset: u16,
    pub dir: &'static str,
    /// True if the param is a top-level ref (`IsSimpleRef`) - NDR marshals the
    /// referent inline (no referent id).
    pub simple_ref: bool,
    pub node: Node,
}

/// Where a conformant/varying length comes from.
#[derive(Debug, Serialize)]
#[serde(tag = "from", rename_all = "snake_case")]
pub enum LengthSource {
    /// From another parameter, identified by its stack offset.
    Param { stack_offset: u16 },
    /// From a sibling field at a (signed) memory offset.
    Field { offset: i32 },
    /// Present but not statically resolvable.
    Runtime,
}

/// One arm of a union in the grammar.
#[derive(Debug, Serialize)]
pub struct GrammarArm {
    pub case: i64,
    pub node: Box<Node>,
}

/// A fuzzable value node.
#[derive(Debug, Serialize)]
#[serde(tag = "node", rename_all = "snake_case")]
pub enum Node {
    /// An integer of `bytes` width.
    Int { bytes: u8, signed: bool },
    /// A floating-point value.
    Float { bytes: u8 },
    /// An integer constrained to `[min, max]` - mutate around the bounds.
    Range { bytes: u8, min: i64, max: i64 },
    /// A pointer. `nullable` reflects unique/full vs. ref semantics.
    Pointer { nullable: bool, pointee: Box<Node> },
    /// A structure of ordered fields.
    Struct { size: u16, fields: Vec<Node> },
    /// A conformant (optionally varying) array.
    Array {
        element: Box<Node>,
        length: LengthSource,
        varying: bool,
    },
    /// A fixed-size inline array (`total_bytes` on the wire).
    FixedArray {
        element: Box<Node>,
        total_bytes: u32,
    },
    /// A NUL-terminated string.
    Str { wide: bool },
    /// A COM interface pointer (marshaled as an OBJREF).
    InterfacePtr {
        #[serde(skip_serializing_if = "Option::is_none")]
        iid: Option<String>,
    },
    /// A 20-byte NDR context handle.
    ContextHandle,
    /// A discriminated union.
    Union {
        encapsulated: bool,
        tag_bytes: u8,
        arms: Vec<GrammarArm>,
    },
    /// A user-marshalled type; `wire` is the underlying NDR representation.
    UserMarshal { wire: Box<Node> },
    /// Opaque bytes - an unresolved/unsupported type. Still fuzzable.
    Blob { fc: u8, note: &'static str },
}

const NDR_NOTES: &str =
    "NDR wire rules the harness must apply: little-endian; each primitive aligned \
     to its own size; conformant array max_count (ulong) is marshaled BEFORE the \
     containing struct/array; varying arrays add offset+actual_count; unique/full \
     pointers emit a non-zero referent id when present (ref pointers do not); \
     context handles are 20 bytes.";

/// Build a grammar for one interface from its decoded procedures.
pub fn build_interface_grammar(uuid: &str, version: Version, procs: &[Procedure]) -> FuzzGrammar {
    let methods = procs.iter().map(build_method).collect();
    FuzzGrammar {
        interface: uuid.to_string(),
        version: version.to_string(),
        ndr_notes: NDR_NOTES,
        methods,
    }
}

fn build_method(proc: &Procedure) -> MethodGrammar {
    let mut request = Vec::new();
    let mut response = Vec::new();
    for p in &proc.params {
        let field = Field {
            stack_offset: p.stack_offset,
            dir: dir_str(p.dir),
            simple_ref: p.simple_ref,
            node: map_type(&p.ty),
        };
        match p.dir {
            ParamDir::In | ParamDir::InOut => request.push(field),
            ParamDir::Out | ParamDir::Return => response.push(field),
        }
    }
    MethodGrammar {
        opnum: proc.proc_num,
        handler_rva: proc.routine_rva,
        request,
        response,
    }
}

fn dir_str(d: ParamDir) -> &'static str {
    match d {
        ParamDir::In => "in",
        ParamDir::Out => "out",
        ParamDir::InOut => "in_out",
        ParamDir::Return => "return",
    }
}

/// Map a decoded [`TypeRef`] to a fuzzing [`Node`].
fn map_type(t: &TypeRef) -> Node {
    match t {
        TypeRef::Base { fc, size, .. } => base_node(*fc, *size),
        TypeRef::Str { wide, .. } => Node::Str { wide: *wide },
        TypeRef::Pointer { fc, pointee, .. } => Node::Pointer {
            nullable: *fc != FC_RP, // ref pointers are non-null; unique/full may be null
            pointee: Box::new(map_type(pointee)),
        },
        TypeRef::Struct { size, members, .. } => Node::Struct {
            size: *size,
            fields: members.iter().map(map_type).collect(),
        },
        TypeRef::Array {
            element,
            conformance,
            fc,
            ..
        } => Node::Array {
            element: Box::new(map_type(element)),
            length: length_source(conformance.as_ref()),
            varying: matches!(*fc, FC_CVARRAY | FC_CVSTRUCT | FC_SMVARRAY | FC_LGVARRAY),
        },
        TypeRef::FixedArray {
            element,
            total_size,
            ..
        } => Node::FixedArray {
            element: Box::new(map_type(element)),
            total_bytes: *total_size,
        },
        TypeRef::Range {
            base_fc, min, max, ..
        } => Node::Range {
            bytes: opcodes::simple_type_size(*base_fc).unwrap_or(4),
            min: *min,
            max: *max,
        },
        TypeRef::InterfacePtr { iid, .. } => Node::InterfacePtr { iid: iid.clone() },
        TypeRef::ContextHandle { .. } => Node::ContextHandle,
        TypeRef::Union {
            encapsulated,
            switch_fc,
            arms,
            ..
        } => Node::Union {
            encapsulated: *encapsulated,
            tag_bytes: opcodes::simple_type_size(*switch_fc).unwrap_or(4),
            arms: arms
                .iter()
                .map(|a| GrammarArm {
                    case: a.case_value,
                    node: Box::new(map_type(&a.ty)),
                })
                .collect(),
        },
        TypeRef::UserMarshal { wire, .. } => Node::UserMarshal {
            wire: Box::new(map_type(wire)),
        },
        TypeRef::Unresolved { fc, name, .. } => Node::Blob {
            fc: *fc,
            note: name,
        },
    }
}

fn base_node(fc: u8, size: u8) -> Node {
    match fc {
        FC_FLOAT => Node::Float { bytes: 4 },
        FC_DOUBLE => Node::Float { bytes: 8 },
        _ => Node::Int {
            bytes: size,
            signed: is_signed(fc),
        },
    }
}

fn is_signed(fc: u8) -> bool {
    matches!(
        fc,
        FC_CHAR | FC_SMALL | FC_SHORT | FC_LONG | FC_HYPER | FC_ENUM16 | FC_ENUM32 | FC_INT3264
    )
}

fn length_source(corr: Option<&Correlation>) -> LengthSource {
    match corr {
        Some(c) if c.raw_type & 0xf0 == 0 => LengthSource::Field {
            offset: c.offset as i16 as i32,
        },
        Some(c) if c.raw_type & 0xf0 == 0x20 => LengthSource::Param {
            stack_offset: c.offset,
        },
        Some(_) => LengthSource::Runtime,
        None => LengthSource::Runtime,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ndr::Param;

    fn base(fc: u8, size: u8) -> TypeRef {
        TypeRef::Base {
            fc,
            name: opcodes::fc_name(fc),
            size,
        }
    }

    /// A `size_is(count)` array param + an `[out]` return should split the
    /// grammar into a request (the sized array, length sourced from the count
    /// param) and a response (the return value).
    #[test]
    fn conformance_and_direction_split() {
        let proc = Procedure {
            proc_num: 7,
            name: None,
            fmt_offset: 0,
            routine_rva: Some(0x1234),
            params: vec![
                Param {
                    dir: ParamDir::In,
                    stack_offset: 8,
                    attributes: 0,
                    simple_ref: false,
                    ty: base(FC_LONG, 4),
                },
                Param {
                    dir: ParamDir::In,
                    stack_offset: 16,
                    attributes: 0,
                    simple_ref: false,
                    ty: TypeRef::Array {
                        fc: FC_CARRAY,
                        name: "FC_CARRAY",
                        element_size: 4,
                        element: Box::new(base(FC_LONG, 4)),
                        // raw_type 0x28 => param-relative, offset 8 (the count).
                        conformance: Some(Correlation {
                            raw_type: 0x28,
                            count_fc: FC_LONG,
                            offset: 8,
                            flags: 1,
                        }),
                    },
                },
                Param {
                    dir: ParamDir::Return,
                    stack_offset: 24,
                    attributes: 0,
                    simple_ref: false,
                    ty: base(FC_LONG, 4),
                },
            ],
        };

        let g = build_method(&proc);
        assert_eq!(g.opnum, 7);
        assert_eq!(g.handler_rva, Some(0x1234));
        assert_eq!(g.request.len(), 2);
        assert_eq!(g.response.len(), 1);

        match &g.request[1].node {
            Node::Array {
                length, varying, ..
            } => {
                assert!(!varying);
                match length {
                    LengthSource::Param { stack_offset } => assert_eq!(*stack_offset, 8),
                    other => panic!("expected param length source, got {other:?}"),
                }
            }
            other => panic!("expected array node, got {other:?}"),
        }
    }

    #[test]
    fn base_signedness_and_floats() {
        assert!(matches!(
            base_node(FC_BYTE, 1),
            Node::Int { signed: false, .. }
        ));
        assert!(matches!(
            base_node(FC_SMALL, 1),
            Node::Int { signed: true, .. }
        ));
        assert!(matches!(base_node(FC_DOUBLE, 8), Node::Float { bytes: 8 }));
    }
}
