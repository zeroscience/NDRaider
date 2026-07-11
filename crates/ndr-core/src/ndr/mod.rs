//! NDR format-string interpretation (milestone **M2**).
//!
//! Given a candidate interface found by [`crate::interface`], follow the pointer
//! chain the MIDL compiler lays down and decode each method's parameter list:
//!
//! ```text
//! RPC_SERVER_INTERFACE.InterpreterInfo
//!   -> MIDL_SERVER_INFO { pStubDesc, ProcString, FmtStringOffset[] }
//!        pStubDesc -> MIDL_STUB_DESC { pFormatTypes -> type format string }
//! ```
//!
//! For each method we walk the procedure format string at its offset: an `Oi2`
//! header, then one 6-byte descriptor per parameter. Simple params carry an
//! inline base-type `FC_*`; complex params carry a `u16` offset into the *type*
//! format string, which we recurse into. Exact layouts and offsets are in
//! `docs/NDR_NOTES.md`, validated against the `samples/ndrtest` oracle.
//!
//! The end product is [`Procedure`]/[`Param`]/[`TypeRef`] - a structured,
//! serializable model that M4 turns into a fuzzing grammar.

pub mod interp;
pub mod opcodes;

use crate::interface::RpcInterface;
use crate::pe::PeImage;
use serde::Serialize;

/// A decoded RPC method.
#[derive(Debug, Clone, Serialize)]
pub struct Procedure {
    /// Method index within the interface (dispatch/proc number).
    pub proc_num: u32,
    /// Method name if recoverable (usually absent in stripped stubs).
    pub name: Option<String>,
    /// Parameters in declaration order (may include the return value).
    pub params: Vec<Param>,
    /// Offset of this proc within the concatenated procedure format string.
    pub fmt_offset: u32,
    /// RVA of the server-side handler function for this method (from the
    /// `SERVER_ROUTINE` dispatch table), when recoverable. Lets consumers name
    /// the actual handler in a disassembler.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routine_rva: Option<u32>,
}

/// Direction of a parameter, from the `PARAM_ATTRIBUTES` bits.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParamDir {
    In,
    Out,
    InOut,
    Return,
}

/// A single method parameter.
#[derive(Debug, Clone, Serialize)]
pub struct Param {
    pub dir: ParamDir,
    /// Byte offset of the argument on the RPC stack (from the descriptor).
    pub stack_offset: u16,
    /// Raw `PARAM_ATTRIBUTES` bitfield, preserved for transparency/debugging.
    pub attributes: u16,
    /// `true` if the parameter is a top-level `*` handled by reference
    /// (`IsSimpleRef`); the pointer is implicit and `ty` is the pointee.
    pub simple_ref: bool,
    /// The parameter's type.
    pub ty: TypeRef,
}

/// A conformance/variance correlation descriptor (e.g. `size_is(count)`), which
/// ties an array/string length to another parameter or field.
#[derive(Debug, Clone, Serialize)]
pub struct Correlation {
    /// Raw correlation-type byte (high nibble = where the count comes from,
    /// low nibble = the count's `FC_*` type).
    pub raw_type: u8,
    /// `FC_*` of the count value (low nibble of `raw_type`).
    pub count_fc: u8,
    /// Stack/field offset the count is read from.
    pub offset: u16,
    /// Correlation flags (e.g. `0x1` = early-evaluated).
    pub flags: u16,
}

/// A (possibly recursive) reference to a decoded NDR type.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeRef {
    /// A simple base type, named by its `FC_*` code.
    Base {
        fc: u8,
        name: &'static str,
        size: u8,
    },
    /// A pointer (`FC_RP`/`FC_UP`/`FC_OP`/`FC_FP`) to another type.
    Pointer {
        fc: u8,
        name: &'static str,
        /// Pointer flags byte (0x08 = simple pointer, 0x04 = alloced on stack…).
        ptr_flags: u8,
        pointee: Box<TypeRef>,
    },
    /// A structure with its member types (simple structs fully; complex members
    /// may appear as `Unresolved` in this first pass).
    Struct {
        fc: u8,
        name: &'static str,
        size: u16,
        members: Vec<TypeRef>,
    },
    /// A conformant/fixed array of `element`.
    Array {
        fc: u8,
        name: &'static str,
        element_size: u16,
        element: Box<TypeRef>,
        /// Conformance descriptor for sized arrays (`None` for fixed arrays).
        conformance: Option<Correlation>,
    },
    /// A string type (`FC_C_WSTRING`, `FC_C_CSTRING`, …).
    Str {
        fc: u8,
        name: &'static str,
        wide: bool,
    },
    /// A fixed-size inline array (`FC_SMFARRAY` / `FC_LGFARRAY`).
    FixedArray {
        fc: u8,
        name: &'static str,
        total_size: u32,
        element: Box<TypeRef>,
    },
    /// A `[range]`-constrained scalar (`FC_RANGE`).
    Range {
        fc: u8,
        name: &'static str,
        base_fc: u8,
        base_name: &'static str,
        min: i64,
        max: i64,
    },
    /// A COM/OLE interface pointer (`FC_IP`). `iid` is set when the interface is
    /// pinned by a constant IID (`FC_CONSTANT_IID`).
    InterfacePtr {
        fc: u8,
        name: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        iid: Option<String>,
    },
    /// A context handle (`FC_BIND_CONTEXT`).
    ContextHandle {
        fc: u8,
        name: &'static str,
        ctx_flags: u8,
    },
    /// A discriminated union (`FC_ENCAPSULATED_UNION` / non-encapsulated).
    Union {
        fc: u8,
        name: &'static str,
        encapsulated: bool,
        /// `FC_*` of the discriminant/switch value.
        switch_fc: u8,
        arms: Vec<UnionArm>,
    },
    /// A user-marshalled type (`FC_USER_MARSHAL`, e.g. `BSTR`, `VARIANT`).
    /// `wire` is the underlying NDR wire representation the harness marshals.
    UserMarshal {
        fc: u8,
        name: &'static str,
        mem_size: u16,
        wire: Box<TypeRef>,
    },
    /// A type we recognized the code of but haven't fully decoded yet. Carries
    /// the raw `FC_*` so downstream tooling and humans see exactly what's left.
    Unresolved {
        fc: u8,
        name: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        note: Option<String>,
    },
}

/// One arm of a discriminated [`TypeRef::Union`].
#[derive(Debug, Clone, Serialize)]
pub struct UnionArm {
    /// The discriminant value selecting this arm.
    pub case_value: i64,
    pub ty: Box<TypeRef>,
}

impl TypeRef {
    /// Build an `Unresolved` from just a format code.
    pub(crate) fn unresolved(fc: u8) -> TypeRef {
        TypeRef::Unresolved {
            fc,
            name: opcodes::fc_name(fc),
            note: None,
        }
    }
}

/// Errors specific to format-string interpretation. These are "expected"
/// conditions for hostile/odd binaries - the interpreter degrades gracefully
/// rather than panicking.
#[derive(Debug, thiserror::Error)]
pub enum InterpretError {
    /// The interface has no server-side interpreter info (e.g. a client-only
    /// stub); there are no procedures to decode from it.
    #[error("no MIDL_SERVER_INFO (client-only interface or non-MIDL stub)")]
    NoServerInfo,

    /// A pointer in the chain didn't resolve to readable image data.
    #[error("broken pointer chain at {stage}")]
    BrokenChain { stage: &'static str },

    #[error(transparent)]
    Pe(#[from] crate::error::NdrError),
}

/// Decode all procedures for one interface.
pub fn interpret_interface(
    pe: &PeImage,
    iface: &RpcInterface,
) -> Result<Vec<Procedure>, InterpretError> {
    interp::interpret_interface(pe, iface)
}
