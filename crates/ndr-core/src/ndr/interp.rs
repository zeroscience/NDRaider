//! The NDR format-string interpreter (M2 implementation).
//!
//! Three stages, each traceable to `docs/NDR_NOTES.md`:
//!   1. [`walk_chain`] - interface struct → `MIDL_SERVER_INFO` → the three
//!      pointers we need (ProcString, FmtStringOffset, type format string) plus
//!      the method count from the dispatch table.
//!   2. [`decode_proc`] - parse one procedure's Oi2 header + parameter list.
//!   3. [`decode_type`] - recursively decode a complex type from the type
//!      format string.
//!
//! Everything is bounds-checked and depth-limited: malformed or hostile input
//! yields `Unresolved`/errors, never a panic.

use super::opcodes::{self, *};
use super::{Correlation, InterpretError, Param, ParamDir, Procedure, TypeRef};
use crate::interface::RpcInterface;
use crate::pe::PeImage;

/// Guards against cyclic/adversarial type graphs.
const MAX_TYPE_DEPTH: u32 = 32;
/// Sanity cap so a corrupt count field can't make us allocate forever.
const MAX_PROCS: u32 = 4096;
const MAX_PARAMS: u8 = 128;

// --- PARAM_ATTRIBUTES bits ------------------------------------------------
// (MustSize 0x0001 / MustFree 0x0002 are documented in NDR_NOTES but not
// needed for structural decoding.)
const PA_IS_IN: u16 = 0x0008;
const PA_IS_OUT: u16 = 0x0010;
const PA_IS_RETURN: u16 = 0x0020;
const PA_IS_BASETYPE: u16 = 0x0040;
const PA_IS_SIMPLE_REF: u16 = 0x0100;

// --- Oi2 proc flags -------------------------------------------------------
const OI2_HAS_EXTENSIONS: u8 = 0x40;

// --- pointer flags --------------------------------------------------------
const PTR_SIMPLE: u8 = 0x08;

/// Field offsets that differ by pointer width. Filled from `NDR_NOTES.md`.
struct Layout {
    /// `RPC_SERVER_INTERFACE` → `InterpreterInfo` (MIDL_SERVER_INFO ptr).
    iface_interpreter_info: u32,
    /// `RPC_SERVER_INTERFACE` → `DispatchTable` (RPC_DISPATCH_TABLE ptr).
    iface_dispatch_table: u32,
    /// `MIDL_SERVER_INFO` → `pStubDesc`.
    si_stub_desc: u32,
    /// `MIDL_SERVER_INFO` → `DispatchTable` (SERVER_ROUTINE function pointers).
    si_dispatch_table: u32,
    /// `MIDL_SERVER_INFO` → `ProcString`.
    si_proc_string: u32,
    /// `MIDL_SERVER_INFO` → `FmtStringOffset`.
    si_fmt_offset: u32,
    /// `MIDL_STUB_DESC` → `pFormatTypes` (type format string).
    stub_format_types: u32,
}

impl Layout {
    fn for_image(pe: &PeImage) -> Self {
        if pe.is_64bit {
            Layout {
                iface_interpreter_info: 0x50,
                iface_dispatch_table: 0x30,
                si_stub_desc: 0x00,
                si_dispatch_table: 0x08,
                si_proc_string: 0x10,
                si_fmt_offset: 0x18,
                stub_format_types: 0x40,
            }
        } else {
            Layout {
                iface_interpreter_info: 0x3c,
                iface_dispatch_table: 0x2c,
                si_stub_desc: 0x00,
                si_dispatch_table: 0x04,
                si_proc_string: 0x08,
                si_fmt_offset: 0x0c,
                stub_format_types: 0x20,
            }
        }
    }
}

/// Resolved pointers/counts from the interface's server info.
struct Chain {
    proc_string_rva: u32,
    fmt_offset_rva: u32,
    type_format_rva: u32,
    /// RVA of the `SERVER_ROUTINE` function-pointer table, if resolvable.
    dispatch_routines_rva: Option<u32>,
    method_count: u32,
}

/// Convert a stored virtual address (preferred base) into an RVA.
fn va_to_rva(pe: &PeImage, va: u64) -> Option<u32> {
    if va == 0 {
        return None;
    }
    u32::try_from(va.checked_sub(pe.image_base)?).ok()
}

/// Read a native pointer at `rva` and turn it into an RVA that maps to data.
fn read_ptr_rva(pe: &PeImage, rva: u32) -> Option<u32> {
    let va = pe.read_ptr_at_rva(rva).ok()?;
    let target = va_to_rva(pe, va)?;
    // Must land in a real section, else it's not a usable pointer.
    pe.rva_to_offset(target)?;
    Some(target)
}

/// Stage 1: walk the pointer chain from the interface struct.
fn walk_chain(pe: &PeImage, iface: &RpcInterface, l: &Layout) -> Result<Chain, InterpretError> {
    let base = iface.struct_rva;

    let server_info_rva =
        read_ptr_rva(pe, base + l.iface_interpreter_info).ok_or(InterpretError::NoServerInfo)?;

    let proc_string_rva = read_ptr_rva(pe, server_info_rva + l.si_proc_string).ok_or(
        InterpretError::BrokenChain {
            stage: "ProcString",
        },
    )?;
    let fmt_offset_rva =
        read_ptr_rva(pe, server_info_rva + l.si_fmt_offset).ok_or(InterpretError::BrokenChain {
            stage: "FmtStringOffset",
        })?;
    let stub_desc_rva = read_ptr_rva(pe, server_info_rva + l.si_stub_desc)
        .ok_or(InterpretError::BrokenChain { stage: "pStubDesc" })?;
    let type_format_rva = read_ptr_rva(pe, stub_desc_rva + l.stub_format_types).ok_or(
        InterpretError::BrokenChain {
            stage: "pFormatTypes",
        },
    )?;

    // Optional: the SERVER_ROUTINE table (function pointers per method). Not
    // fatal if absent - we just won't have handler addresses.
    let dispatch_routines_rva = read_ptr_rva(pe, server_info_rva + l.si_dispatch_table);

    // Method count from RPC_DISPATCH_TABLE.DispatchTableCount (u32 at +0x00).
    let dispatch_rva =
        read_ptr_rva(pe, base + l.iface_dispatch_table).ok_or(InterpretError::BrokenChain {
            stage: "DispatchTable",
        })?;
    let method_count =
        pe.read_u32_at_rva(dispatch_rva)
            .map_err(|_| InterpretError::BrokenChain {
                stage: "DispatchTableCount",
            })?;
    if method_count > MAX_PROCS {
        return Err(InterpretError::BrokenChain {
            stage: "DispatchTableCount(too large)",
        });
    }

    Ok(Chain {
        proc_string_rva,
        fmt_offset_rva,
        type_format_rva,
        dispatch_routines_rva,
        method_count,
    })
}

/// Diagnostic: resolve the type format string for an interface and return its
/// RVA plus a bounded byte snapshot. Used by `ndr-cli dumptypes` to inspect raw
/// NDR layouts (offset/opcode) when validating the interpreter.
pub fn type_format_blob(pe: &PeImage, iface: &RpcInterface) -> Option<(u32, Vec<u8>)> {
    let layout = Layout::for_image(pe);
    let chain = walk_chain(pe, iface, &layout).ok()?;
    Some((
        chain.type_format_rva,
        read_format_blob(pe, chain.type_format_rva),
    ))
}

pub fn interpret_interface(
    pe: &PeImage,
    iface: &RpcInterface,
) -> Result<Vec<Procedure>, InterpretError> {
    let layout = Layout::for_image(pe);
    let chain = walk_chain(pe, iface, &layout)?;

    // Snapshot the proc and type format strings into owned buffers so the
    // cursor logic is plain slice indexing. They live in the same section and
    // are modestly sized; read a generous bounded window from each.
    let proc_fmt = read_format_blob(pe, chain.proc_string_rva);
    let type_fmt = read_format_blob(pe, chain.type_format_rva);

    let mut procs = Vec::new();
    for i in 0..chain.method_count {
        let off_rva = chain.fmt_offset_rva + i * 2;
        let Ok(fmt_off) = pe.read_u16_at_rva(off_rva) else {
            break;
        };
        let routine_rva = resolve_routine_rva(pe, &layout, chain.dispatch_routines_rva, i);
        let mut proc =
            decode_proc(pe, &proc_fmt, &type_fmt, i, fmt_off as usize).unwrap_or_else(|| {
                Procedure {
                    // Placeholder keeps method indices meaningful if a proc fails.
                    proc_num: i,
                    name: None,
                    params: Vec::new(),
                    fmt_offset: fmt_off as u32,
                    routine_rva: None,
                }
            });
        proc.routine_rva = routine_rva;
        procs.push(proc);
    }
    Ok(procs)
}

/// Resolve the handler function RVA for proc `i` from the `SERVER_ROUTINE`
/// table (an array of native function pointers).
fn resolve_routine_rva(
    pe: &PeImage,
    _layout: &Layout,
    routines_rva: Option<u32>,
    i: u32,
) -> Option<u32> {
    let base = routines_rva?;
    let slot = base + i * pe.pointer_size() as u32;
    read_ptr_rva(pe, slot)
}

/// Read a format string as an owned byte buffer. Format strings have no length
/// header; we read to the end of the containing section (bounded), which is
/// always enough since the cursor logic never runs past the real terminator.
fn read_format_blob(pe: &PeImage, rva: u32) -> Vec<u8> {
    // Find the section end for this RVA to size the read; fall back to a cap.
    const CAP: usize = 64 * 1024;
    for (sec, _) in pe.section_slices() {
        let start = sec.virtual_address;
        let end = start as u64 + sec.virtual_size as u64;
        if (rva as u64) >= start as u64 && (rva as u64) < end {
            let avail = (end - rva as u64) as usize;
            let len = avail.min(CAP);
            if let Ok(b) = pe.bytes_at_rva(rva, len) {
                return b.to_vec();
            }
        }
    }
    Vec::new()
}

/// Stage 2: decode one procedure's Oi2 header and parameter descriptors.
fn decode_proc(
    _pe: &PeImage,
    proc_fmt: &[u8],
    type_fmt: &[u8],
    proc_num: u32,
    start: usize,
) -> Option<Procedure> {
    let mut c = Cursor::new(proc_fmt, start);

    let handle_type = c.u8()?;
    let _oi_flags = c.u8()?;
    let _rpc_flags = c.u32()?; // ms_ext interpreter: rpc_flags present
    let _proc_num_field = c.u16()?;
    let _stack_size = c.u16()?;

    // Explicit handle descriptor (handle_type == 0). Implicit handles consume
    // no bytes here.
    if handle_type == 0 {
        let hfc = c.peek_u8()?;
        let hlen = match hfc {
            FC_BIND_PRIMITIVE => 4, // fc, flag, u16 offset
            FC_BIND_GENERIC | FC_BIND_CONTEXT => 6,
            _ => 0, // unknown/none - don't advance
        };
        c.skip(hlen)?;
    }

    // Oi2 descriptor.
    let _client_buf = c.u16()?;
    let _server_buf = c.u16()?;
    let oi2_flags = c.u8()?;
    let num_params = c.u8()?;

    if oi2_flags & OI2_HAS_EXTENSIONS != 0 {
        let ext_size = c.peek_u8()? as usize;
        // ext_size counts from the size byte through the end of the extension.
        c.skip(ext_size.max(1))?;
    }

    if num_params > MAX_PARAMS {
        return None;
    }

    let mut params = Vec::with_capacity(num_params as usize);
    for _ in 0..num_params {
        let attrs = c.u16()?;
        let stack_offset = c.u16()?;

        let ty = if attrs & PA_IS_BASETYPE != 0 {
            let fc = c.u8()?;
            let _pad = c.u8()?;
            base_type(fc)
        } else {
            let type_off = c.u16()?;
            decode_type(type_fmt, type_off as usize, 0)
        };

        params.push(Param {
            dir: dir_from_attrs(attrs),
            stack_offset,
            attributes: attrs,
            simple_ref: attrs & PA_IS_SIMPLE_REF != 0,
            ty,
        });
    }

    // routine_rva is filled in by the caller (it owns the dispatch table).
    Some(Procedure {
        proc_num,
        name: None,
        params,
        fmt_offset: start as u32,
        routine_rva: None,
    })
}

fn dir_from_attrs(attrs: u16) -> ParamDir {
    if attrs & PA_IS_RETURN != 0 {
        ParamDir::Return
    } else if attrs & PA_IS_IN != 0 && attrs & PA_IS_OUT != 0 {
        ParamDir::InOut
    } else if attrs & PA_IS_OUT != 0 {
        ParamDir::Out
    } else {
        ParamDir::In
    }
}

/// Map a base-type `FC_*` to a `TypeRef::Base`, or `Unresolved` if it isn't one.
fn base_type(fc: u8) -> TypeRef {
    match opcodes::simple_type_size(fc) {
        Some(size) => TypeRef::Base {
            fc,
            name: opcodes::fc_name(fc),
            size,
        },
        // Platform ints wire as 4 bytes under classic NDR.
        None if matches!(fc, FC_INT3264 | FC_UINT3264) => TypeRef::Base {
            fc,
            name: opcodes::fc_name(fc),
            size: 4,
        },
        None => TypeRef::unresolved(fc),
    }
}

/// Is `fc` a base type that can appear inline as a single-byte struct member?
fn is_base_member(fc: u8) -> bool {
    opcodes::simple_type_size(fc).is_some() || matches!(fc, FC_INT3264 | FC_UINT3264)
}

/// Stage 3: recursively decode a type at `off` within the type format string.
fn decode_type(fmt: &[u8], off: usize, depth: u32) -> TypeRef {
    if depth > MAX_TYPE_DEPTH {
        return TypeRef::Unresolved {
            fc: 0,
            name: "FC_UNKNOWN",
            note: Some("max depth".into()),
        };
    }
    let Some(&fc) = fmt.get(off) else {
        return TypeRef::unresolved(0);
    };

    // Simple/base types can appear inline in the type string too.
    if let Some(size) = opcodes::simple_type_size(fc) {
        return TypeRef::Base {
            fc,
            name: opcodes::fc_name(fc),
            size,
        };
    }

    // Landing on FC_ZERO (0x00) during type decode means we lost the element -
    // almost always variable/expression conformance we can't yet traverse (see
    // NDR_NOTES). Label it honestly instead of pretending it's a real type.
    if fc == FC_ZERO {
        return TypeRef::Unresolved {
            fc: 0,
            name: "FC_ZERO",
            note: Some("unresolved element - variable/expression conformance".into()),
        };
    }

    match fc {
        // A redirect: [FC_EMBEDDED_COMPLEX][reserved][i16 offset to real type].
        FC_EMBEDDED_COMPLEX => match read_i16(fmt, off + 2) {
            Some(rel) => {
                let target = (off as isize + 2 + rel as isize).max(0) as usize;
                decode_type(fmt, target, depth + 1)
            }
            None => TypeRef::unresolved(fc),
        },
        FC_RP | FC_UP | FC_OP | FC_FP => decode_pointer(fmt, off, fc, depth),
        FC_STRUCT | FC_PSTRUCT => decode_struct(fmt, off, fc, depth),
        FC_CSTRUCT | FC_CPSTRUCT | FC_CVSTRUCT => decode_cstruct(fmt, off, fc, depth),
        FC_BOGUS_STRUCT => decode_bogus_struct(fmt, off, fc, depth),
        FC_CARRAY => decode_carray(fmt, off, fc, depth),
        FC_CVARRAY => decode_cvarray(fmt, off, fc, depth),
        FC_BOGUS_ARRAY => decode_bogus_array(fmt, off, fc, depth),
        FC_SMFARRAY | FC_LGFARRAY => decode_fixed_array(fmt, off, fc, depth),
        FC_SMVARRAY | FC_LGVARRAY => decode_varying_fixed_array(fmt, off, fc, depth),
        FC_USER_MARSHAL => decode_user_marshal(fmt, off, fc, depth),
        FC_RANGE => decode_range(fmt, off, fc),
        FC_IP => decode_interface_ptr(fmt, off, fc),
        FC_BIND_CONTEXT => decode_context_handle(fmt, off, fc),
        FC_ENCAPSULATED_UNION => decode_enc_union(fmt, off, fc, depth),
        FC_NON_ENCAPSULATED_UNION => decode_nonenc_union(fmt, off, fc, depth),
        FC_C_CSTRING | FC_CSTRING => TypeRef::Str {
            fc,
            name: fc_name(fc),
            wide: false,
        },
        FC_C_WSTRING | FC_WSTRING => TypeRef::Str {
            fc,
            name: fc_name(fc),
            wide: true,
        },
        // Platform-width integers: under classic NDR they wire as 4 bytes.
        FC_INT3264 | FC_UINT3264 => TypeRef::Base {
            fc,
            name: fc_name(fc),
            size: 4,
        },
        _ => TypeRef::unresolved(fc),
    }
}

/// `FC_SMFARRAY` (u16 size) / `FC_LGFARRAY` (u32 size): fixed inline array.
/// Layout: `[FC][align][size][element type…][FC_END]`.
fn decode_fixed_array(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let (total_size, elem_off) = if fc == FC_LGFARRAY {
        (read_u32(fmt, off + 2).unwrap_or(0), off + 6)
    } else {
        (read_u16(fmt, off + 2).unwrap_or(0) as u32, off + 4)
    };
    let element = Box::new(decode_type(fmt, elem_off, depth + 1));
    TypeRef::FixedArray {
        fc,
        name: fc_name(fc),
        total_size,
        element,
    }
}

/// `FC_SMVARRAY` (u16 sizes) / `FC_LGVARRAY` (u32 sizes): a fixed-capacity array
/// with a `length_is` varying portion.
/// SM: `[FC][align][u16 total][u16 num][u16 elem_size][variance 6][element…]`
/// (element at off+14). LG widens `total`/`num` to u32 (element at off+18).
fn decode_varying_fixed_array(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let (element_size, corr_off, elem_off) = if fc == FC_LGVARRAY {
        (read_u16(fmt, off + 10).unwrap_or(0), off + 12, off + 18)
    } else {
        (read_u16(fmt, off + 6).unwrap_or(0), off + 8, off + 14)
    };
    let conformance = correlation_at(fmt, corr_off); // this is the length_is variance
    let element = Box::new(decode_type(fmt, elem_off, depth + 1));
    TypeRef::Array {
        fc,
        name: fc_name(fc),
        element_size,
        element,
        conformance,
    }
}

/// `FC_USER_MARSHAL` (e.g. BSTR): `[FC][flags][u16 routine_idx][u16 mem_size]`
/// `[u16 flags2][i16 →wire_type]`. The wire type (relative to off+8) is what the
/// harness actually marshals.
fn decode_user_marshal(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let mem_size = read_u16(fmt, off + 4).unwrap_or(0);
    let wire = match read_i16(fmt, off + 8) {
        Some(rel) => {
            let target = (off as isize + 8 + rel as isize).max(0) as usize;
            Box::new(decode_type(fmt, target, depth + 1))
        }
        None => Box::new(TypeRef::unresolved(fc)),
    };
    TypeRef::UserMarshal {
        fc,
        name: fc_name(fc),
        mem_size,
        wire,
    }
}

/// `FC_RANGE`: `[FC][base_fc][i32 min][i32 max]`.
fn decode_range(fmt: &[u8], off: usize, fc: u8) -> TypeRef {
    let base_fc = fmt.get(off + 1).copied().unwrap_or(0);
    let min = read_i32(fmt, off + 2).unwrap_or(0) as i64;
    let max = read_i32(fmt, off + 6).unwrap_or(0) as i64;
    TypeRef::Range {
        fc,
        name: fc_name(fc),
        base_fc,
        base_name: fc_name(base_fc),
        min,
        max,
    }
}

/// `FC_IP`: interface pointer. When followed by `FC_CONSTANT_IID` the 16-byte
/// IID is inline; otherwise the IID comes from an `iid_is` param at runtime.
fn decode_interface_ptr(fmt: &[u8], off: usize, fc: u8) -> TypeRef {
    let iid = if fmt.get(off + 1) == Some(&FC_CONSTANT_IID) {
        fmt.get(off + 2..off + 18)
            .and_then(|b| <[u8; 16]>::try_from(b).ok())
            .map(|b| crate::types::Guid::from_le_bytes(b).to_string())
    } else {
        None
    };
    TypeRef::InterfacePtr {
        fc,
        name: fc_name(fc),
        iid,
    }
}

/// `FC_BIND_CONTEXT`: `[FC][ctx_flags][rundown_index][ordinal]`.
fn decode_context_handle(fmt: &[u8], off: usize, fc: u8) -> TypeRef {
    let ctx_flags = fmt.get(off + 1).copied().unwrap_or(0);
    TypeRef::ContextHandle {
        fc,
        name: fc_name(fc),
        ctx_flags,
    }
}

/// `FC_CSTRUCT`/`FC_CPSTRUCT`: conformant struct - a fixed part plus a trailing
/// conformant array described elsewhere.
/// Layout: `[FC][align][u16 fixed_size][i16 →array_desc][members][FC_END]`.
fn decode_cstruct(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let size = read_u16(fmt, off + 2).unwrap_or(0);
    let mut members = collect_struct_members(fmt, off + 6, depth);
    // The trailing conformant array lives at the i16 offset (relative to off+4).
    if let Some(rel) = read_i16(fmt, off + 4) {
        let target = (off as isize + 4 + rel as isize).max(0) as usize;
        members.push(decode_type(fmt, target, depth + 1));
    }
    TypeRef::Struct {
        fc,
        name: fc_name(fc),
        size,
        members,
    }
}

/// `FC_BOGUS_STRUCT`: complex struct whose pointer members are described in a
/// separate pointer-layout block.
/// Layout: `[FC][align][u16 size][u16 conf_off][u16 →ptr_layout][members…][FC_END]`
/// where `FC_POINTER` (0x36) placeholders in the member stream consume
/// successive 4-byte pointer descriptors from the pointer-layout block.
fn decode_bogus_struct(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let size = read_u16(fmt, off + 2).unwrap_or(0);
    let ptr_layout =
        read_u16(fmt, off + 6).map(|rel| (off as isize + 6 + rel as i16 as isize).max(0) as usize);

    let mut members = Vec::new();
    let mut i = off + 8;
    let mut ptr_cursor = ptr_layout;
    let mut guard = 0;
    while let Some(&m) = fmt.get(i) {
        if m == FC_END {
            break;
        }
        guard += 1;
        if guard > 256 {
            break;
        }
        if (FC_STRUCTPAD1..=FC_STRUCTPAD7).contains(&m) || m == FC_PAD {
            i += 1;
            continue;
        }
        if m == FC_POINTER {
            // Resolve against the next pointer descriptor in the layout block.
            match ptr_cursor {
                Some(pc) => {
                    members.push(decode_pointer(
                        fmt,
                        pc,
                        fmt.get(pc).copied().unwrap_or(FC_UP),
                        depth + 1,
                    ));
                    ptr_cursor = Some(pc + 4); // pointer descriptors are 4 bytes
                }
                None => members.push(TypeRef::unresolved(m)),
            }
            i += 1;
        } else if opcodes::simple_type_size(m).is_some() {
            members.push(base_type(m));
            i += 1;
        } else if m == FC_EMBEDDED_COMPLEX {
            if let Some(rel) = read_i16(fmt, i + 2) {
                let target = (i as isize + 2 + rel as isize).max(0) as usize;
                members.push(decode_type(fmt, target, depth + 1));
            } else {
                members.push(TypeRef::unresolved(m));
            }
            i += 4;
        } else {
            members.push(TypeRef::unresolved(m));
            i += 1;
        }
    }
    TypeRef::Struct {
        fc,
        name: fc_name(fc),
        size,
        members,
    }
}

/// `FC_ENCAPSULATED_UNION`: `[FC][switch_byte][u16 size][u16 n_arms]` then
/// per-arm `[i32 case][u16 arm_type]`, then `[u16 default_arm]`. An arm type
/// with the `0x8000` bit set is an inline simple `FC_*`; otherwise it's an
/// offset to a complex type.
fn decode_enc_union(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    // [FC][switch_byte][u16 size][u16 n_arms][arms…]
    let switch_fc = fmt.get(off + 1).copied().unwrap_or(0) & 0x0f;
    let n_arms = read_u16(fmt, off + 4).unwrap_or(0);
    let arms = parse_union_arms(fmt, off + 6, n_arms, depth);
    TypeRef::Union {
        fc,
        name: fc_name(fc),
        encapsulated: true,
        switch_fc,
        arms,
    }
}

/// `FC_NON_ENCAPSULATED_UNION`: `[FC][switch_fc][switch_is corr 6]`
/// `[u16 →arms_block]`; at the arms block: `[u16 size][u16 n_arms][arms…]`.
fn decode_nonenc_union(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let switch_fc = fmt.get(off + 1).copied().unwrap_or(0);
    let arms = match read_u16(fmt, off + 8) {
        Some(rel) => {
            let block = off + 8 + rel as usize;
            let n_arms = read_u16(fmt, block + 2).unwrap_or(0);
            parse_union_arms(fmt, block + 4, n_arms, depth)
        }
        None => Vec::new(),
    };
    TypeRef::Union {
        fc,
        name: fc_name(fc),
        encapsulated: false,
        switch_fc,
        arms,
    }
}

/// Read `n_arms` arms of `[i32 case][u16 arm_type]` starting at `p`.
fn parse_union_arms(fmt: &[u8], mut p: usize, n_arms: u16, depth: u32) -> Vec<super::UnionArm> {
    let mut arms = Vec::new();
    for _ in 0..n_arms.min(256) {
        let Some(case_value) = read_i32(fmt, p) else {
            break;
        };
        let Some(arm_raw) = read_u16(fmt, p + 4) else {
            break;
        };
        let ty = decode_arm_type(fmt, p + 4, arm_raw, depth);
        arms.push(super::UnionArm {
            case_value: case_value as i64,
            ty: Box::new(ty),
        });
        p += 6;
    }
    arms
}

/// Decode a union arm type word: `0x8000` bit set = inline simple `FC_*` (low
/// byte); otherwise a signed offset (relative to the word) to a complex type.
fn decode_arm_type(fmt: &[u8], word_off: usize, arm_raw: u16, depth: u32) -> TypeRef {
    if arm_raw == 0 {
        return TypeRef::unresolved(0); // empty arm (e.g. default with no type)
    }
    if arm_raw & 0x8000 != 0 {
        base_type((arm_raw & 0xff) as u8)
    } else {
        let target = (word_off as isize + arm_raw as i16 as isize).max(0) as usize;
        decode_type(fmt, target, depth + 1)
    }
}

/// Collect a simple-struct member run (base types + embedded complex) starting
/// at `start`, until `FC_END`. Shared by simple and conformant structs.
fn collect_struct_members(fmt: &[u8], start: usize, depth: u32) -> Vec<TypeRef> {
    let mut members = Vec::new();
    let mut i = start;
    let mut guard = 0;
    while let Some(&m) = fmt.get(i) {
        if m == FC_END {
            break;
        }
        guard += 1;
        if guard > 256 {
            break;
        }
        if (FC_STRUCTPAD1..=FC_STRUCTPAD7).contains(&m) || m == FC_PAD {
            i += 1;
            continue;
        }
        if is_base_member(m) {
            members.push(base_type(m));
            i += 1;
        } else if m == FC_EMBEDDED_COMPLEX {
            if let Some(rel) = read_i16(fmt, i + 2) {
                let target = (i as isize + 2 + rel as isize).max(0) as usize;
                members.push(decode_type(fmt, target, depth + 1));
            } else {
                members.push(TypeRef::unresolved(m));
            }
            i += 4;
        } else {
            members.push(TypeRef::unresolved(m));
            i += 1;
        }
    }
    members
}

fn decode_pointer(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let name = fc_name(fc);
    let ptr_flags = fmt.get(off + 1).copied().unwrap_or(0);

    let pointee = if ptr_flags & PTR_SIMPLE != 0 {
        // Simple pointer: the pointee's FC is inline at off+2 (+ FC_PAD).
        let p_fc = fmt.get(off + 2).copied().unwrap_or(0);
        Box::new(decode_type(fmt, off + 2, depth + 1).or_inline(p_fc))
    } else {
        // Complex pointer: i16 offset at off+2, relative to that field.
        match read_i16(fmt, off + 2) {
            Some(rel) => {
                let target = (off as isize + 2 + rel as isize).max(0) as usize;
                Box::new(decode_type(fmt, target, depth + 1))
            }
            None => Box::new(TypeRef::unresolved(0)),
        }
    };

    TypeRef::Pointer {
        fc,
        name,
        ptr_flags,
        pointee,
    }
}

fn decode_struct(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    // Simple struct: member layout begins at off+4 and runs until FC_END.
    let size = read_u16(fmt, off + 2).unwrap_or(0);
    let members = collect_struct_members(fmt, off + 4, depth);
    TypeRef::Struct {
        fc,
        name: fc_name(fc),
        size,
        members,
    }
}

/// Parse a robust correlation descriptor at `corr_off`:
/// `[type][reserved][u16 offset][u16 flags]` (6 bytes).
fn correlation_at(fmt: &[u8], corr_off: usize) -> Option<Correlation> {
    fmt.get(corr_off).map(|&raw_type| Correlation {
        raw_type,
        count_fc: raw_type & 0x0f,
        offset: read_u16(fmt, corr_off + 2).unwrap_or(0),
        flags: read_u16(fmt, corr_off + 4).unwrap_or(0),
    })
}

/// `FC_CARRAY` (conformant array): `[FC][align][u16 elem_size]`
/// `[conformance 6][element…][FC_END]`. Element at off+10.
fn decode_carray(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let element_size = read_u16(fmt, off + 2).unwrap_or(0);
    let conformance = correlation_at(fmt, off + 4);
    let element = Box::new(decode_type(fmt, off + 10, depth + 1));
    TypeRef::Array {
        fc,
        name: fc_name(fc),
        element_size,
        element,
        conformance,
    }
}

/// `FC_CVARRAY` (conformant *varying* array): like CARRAY but with an extra
/// variance descriptor, so the header is 16 bytes and the element is at off+16.
fn decode_cvarray(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let element_size = read_u16(fmt, off + 2).unwrap_or(0);
    let conformance = correlation_at(fmt, off + 4); // variance desc lives at off+10
    let element = Box::new(decode_type(fmt, off + 16, depth + 1));
    TypeRef::Array {
        fc,
        name: fc_name(fc),
        element_size,
        element,
        conformance,
    }
}

/// `FC_BOGUS_ARRAY` (complex array): `[FC][align][u16 num_elems]`
/// `[conformance 6][variance 6][element type…][FC_END]` for the conformant case
/// (element at off+16). Fixed bogus arrays (num_elems != 0, no conformance) use
/// a different header and are not fully handled - see NDR_NOTES.
fn decode_bogus_array(fmt: &[u8], off: usize, fc: u8, depth: u32) -> TypeRef {
    let conformance = correlation_at(fmt, off + 4);
    let element = Box::new(decode_type(fmt, off + 16, depth + 1));
    TypeRef::Array {
        fc,
        name: fc_name(fc),
        element_size: 0,
        element,
        conformance,
    }
}

impl TypeRef {
    /// If `self` came back `Unresolved` but we have an inline FC that is a
    /// base/string type, use that instead. Used for simple-pointer pointees.
    fn or_inline(self, inline_fc: u8) -> TypeRef {
        match self {
            TypeRef::Unresolved { .. } => match inline_fc {
                FC_C_WSTRING | FC_WSTRING => TypeRef::Str {
                    fc: inline_fc,
                    name: fc_name(inline_fc),
                    wide: true,
                },
                FC_C_CSTRING | FC_CSTRING => TypeRef::Str {
                    fc: inline_fc,
                    name: fc_name(inline_fc),
                    wide: false,
                },
                _ => base_type(inline_fc),
            },
            other => other,
        }
    }
}

// --- little-endian helpers over a byte slice ------------------------------

fn read_u16(b: &[u8], off: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(off)?, *b.get(off + 1)?]))
}
fn read_i16(b: &[u8], off: usize) -> Option<i16> {
    read_u16(b, off).map(|v| v as i16)
}
fn read_u32(b: &[u8], off: usize) -> Option<u32> {
    let s = b.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn read_i32(b: &[u8], off: usize) -> Option<i32> {
    read_u32(b, off).map(|v| v as i32)
}

/// A bounds-checked forward cursor over a format-string slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8], pos: usize) -> Self {
        Cursor { buf, pos }
    }
    fn u8(&mut self) -> Option<u8> {
        let v = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(v)
    }
    fn peek_u8(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }
    fn u16(&mut self) -> Option<u16> {
        let v = read_u16(self.buf, self.pos)?;
        self.pos += 2;
        Some(v)
    }
    fn u32(&mut self) -> Option<u32> {
        let b = self.buf.get(self.pos..self.pos + 4)?;
        self.pos += 4;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn skip(&mut self, n: usize) -> Option<()> {
        let np = self.pos.checked_add(n)?;
        if np > self.buf.len() {
            return None;
        }
        self.pos = np;
        Some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact TYPE format string from the `samples/ndrtest` oracle
    /// (NdrTest_s.c). Encodes: RP->Point struct, a conformant long array, a
    /// wide string, and an RP->long. Using the real bytes makes this a durable
    /// regression test independent of having MSVC/MIDL to rebuild the DLL.
    fn oracle_type_fmt() -> Vec<u8> {
        vec![
            0x00, 0x00, // 0: leading pad
            0x11, 0x00, // 2: FC_RP, flags 0
            0x02, 0x00, // 4: offset +2 -> pointee at 6
            0x15, 0x03, // 6: FC_STRUCT, align 4
            0x08, 0x00, // 8: size = 8
            0x08, 0x08, // 10: FC_LONG, FC_LONG (members)
            0x5c, 0x5b, // 12: FC_PAD, FC_END
            0x1b, 0x03, // 14: FC_CARRAY, align 4
            0x04, 0x00, // 16: element size 4
            0x28, 0x00, // 18: corr type 0x28 (param, FC_LONG), reserved
            0x08, 0x00, // 20: count stack offset = 8
            0x01, 0x00, // 22: corr flags = early
            0x08, 0x5b, // 24: FC_LONG (element), FC_END
            0x11, 0x08, // 26: FC_RP [simple_pointer]
            0x25, 0x5c, // 28: FC_C_WSTRING, FC_PAD
            0x11, 0x0c, // 30: FC_RP [alloced][simple]
            0x08, 0x5c, // 32: FC_LONG, FC_PAD
            0x00, // 34: trailing
        ]
    }

    #[test]
    fn decodes_simple_struct() {
        let fmt = oracle_type_fmt();
        match decode_type(&fmt, 6, 0) {
            TypeRef::Struct { size, members, .. } => {
                assert_eq!(size, 8);
                assert_eq!(members.len(), 2);
                for m in &members {
                    assert!(matches!(m, TypeRef::Base { fc: FC_LONG, .. }));
                }
            }
            other => panic!("expected struct, got {other:?}"),
        }
    }

    #[test]
    fn decodes_conformant_array_with_correlation() {
        let fmt = oracle_type_fmt();
        match decode_type(&fmt, 14, 0) {
            TypeRef::Array {
                element_size,
                element,
                conformance,
                ..
            } => {
                assert_eq!(element_size, 4);
                assert!(matches!(*element, TypeRef::Base { fc: FC_LONG, .. }));
                let c = conformance.expect("size_is correlation");
                assert_eq!(c.offset, 8); // stack offset of the `count` param
                assert_eq!(c.count_fc, FC_LONG);
            }
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn decodes_wide_string() {
        let fmt = oracle_type_fmt();
        assert!(matches!(
            decode_type(&fmt, 28, 0),
            TypeRef::Str { wide: true, .. }
        ));
    }

    #[test]
    fn decodes_pointer_to_struct() {
        let fmt = oracle_type_fmt();
        match decode_type(&fmt, 2, 0) {
            TypeRef::Pointer { pointee, .. } => {
                assert!(matches!(*pointee, TypeRef::Struct { size: 8, .. }));
            }
            other => panic!("expected pointer, got {other:?}"),
        }
    }

    #[test]
    fn out_of_bounds_offset_is_graceful() {
        let fmt = oracle_type_fmt();
        // Must not panic; returns an Unresolved placeholder.
        let _ = decode_type(&fmt, 9999, 0);
    }

    /// The exact TYPE format string from the `samples/ndrcomplex` oracle
    /// (NdrComplex_s.c), covering the M2.1 complex types.
    fn complex_type_fmt() -> Vec<u8> {
        vec![
            0x00, 0x00, // 0
            0xb7, 0x08, // 2: FC_RANGE, base FC_LONG
            0x00, 0x00, 0x00, 0x00, // 4: min = 0
            0x64, 0x00, 0x00, 0x00, // 8: max = 100
            0x11, 0x00, // 12: FC_RP
            0x08, 0x00, // 14: -> 22
            0x1d, 0x00, // 16: FC_SMFARRAY, align 1
            0x10, 0x00, // 18: size 16
            0x01, 0x5b, // 20: FC_BYTE, FC_END
            0x15, 0x03, // 22: FC_STRUCT (FixedArr)
            0x14, 0x00, // 24: size 20
            0x08, 0x4c, // 26: FC_LONG, FC_EMBEDDED_COMPLEX
            0x00, 0xf3, 0xff, // 28: pad, i16 -13 -> 16
            0x5b, // 31: FC_END
            0x11, 0x00, // 32: FC_RP
            0x0e, 0x00, // 34: -> 48
            0x1b, 0x03, // 36: FC_CARRAY
            0x04, 0x00, // 38: elem size 4
            0x08, 0x00, // 40: corr FC_LONG
            0xfc, 0xff, // 42: offset -4
            0x01, 0x00, // 44: corr flags
            0x08, 0x5b, // 46: FC_LONG, FC_END
            0x17, 0x03, // 48: FC_CSTRUCT (ConfStruct)
            0x04, 0x00, // 50: fixed size 4
            0xf0, 0xff, // 52: i16 -16 -> 36 (the carray)
            0x08, 0x5b, // 54: FC_LONG, FC_END
            0x11, 0x00, // 56: FC_RP
            0x02, 0x00, // 58: -> 60
            0x1a, 0x03, // 60: FC_BOGUS_STRUCT (BogusStruct)
            0x10, 0x00, // 62: size 16
            0x00, 0x00, // 64: conformant offset 0
            0x06, 0x00, // 66: ptr layout -> 72
            0x08, 0x40, // 68: FC_LONG, FC_STRUCTPAD4
            0x36, 0x5b, // 70: FC_POINTER, FC_END
            0x12, 0x08, // 72: FC_UP [simple]
            0x25, 0x5c, // 74: FC_C_WSTRING, FC_PAD
            0x2f, 0x5a, // 76: FC_IP, FC_CONSTANT_IID
            0x00, 0x00, 0x00, 0x00, // 78: IID data1
            0x00, 0x00, // 82: data2
            0x00, 0x00, // 84: data3
            0xc0, 0x00, // 86: data4[0..2]
            0x00, 0x00, // 88
            0x00, 0x00, // 90
            0x00, 0x46, // 92: data4[6..8]
            0x11, 0x04, // 94: FC_RP [alloced]
            0x02, 0x00, // 96: -> 98
            0x30, 0xa0, // 98: FC_BIND_CONTEXT, flags (via ptr, out)
            0x00, 0x00, // 100
            0x30, 0x41, // 102: FC_BIND_CONTEXT, flags (in, no null)
            0x00, 0x00, // 104
            0x11, 0x00, // 106: FC_RP
            0x02, 0x00, // 108: -> 110
            0x2a, 0x88, // 110: FC_ENCAPSULATED_UNION, switch FC_LONG
            0x08, 0x00, // 112: size 8
            0x02, 0x00, // 114: 2 arms
            0x01, 0x00, 0x00, 0x00, // 116: case 1
            0x08, 0x80, // 120: arm 0x8008 -> FC_LONG
            0x02, 0x00, 0x00, 0x00, // 122: case 2
            0x0c, 0x80, // 126: arm 0x800c -> FC_DOUBLE
            0x00, 0x00, // 128: default arm none
            0x00, // 130
        ]
    }

    #[test]
    fn decodes_range() {
        match decode_type(&complex_type_fmt(), 2, 0) {
            TypeRef::Range {
                base_fc, min, max, ..
            } => {
                assert_eq!(base_fc, FC_LONG);
                assert_eq!((min, max), (0, 100));
            }
            other => panic!("expected range, got {other:?}"),
        }
    }

    #[test]
    fn decodes_fixed_array() {
        match decode_type(&complex_type_fmt(), 16, 0) {
            TypeRef::FixedArray {
                total_size,
                element,
                ..
            } => {
                assert_eq!(total_size, 16);
                assert!(matches!(*element, TypeRef::Base { fc: FC_BYTE, .. }));
            }
            other => panic!("expected fixed array, got {other:?}"),
        }
    }

    #[test]
    fn decodes_conformant_struct() {
        // ConfStruct { long len; long items[]; } -> members [long, long[]].
        match decode_type(&complex_type_fmt(), 48, 0) {
            TypeRef::Struct { fc, members, .. } => {
                assert_eq!(fc, FC_CSTRUCT);
                assert!(matches!(members[0], TypeRef::Base { fc: FC_LONG, .. }));
                assert!(matches!(members[1], TypeRef::Array { .. }));
            }
            other => panic!("expected cstruct, got {other:?}"),
        }
    }

    #[test]
    fn decodes_bogus_struct_with_pointer_member() {
        // BogusStruct { long id; wchar_t* name; } -> [long, ptr->wstring].
        match decode_type(&complex_type_fmt(), 60, 0) {
            TypeRef::Struct { fc, members, .. } => {
                assert_eq!(fc, FC_BOGUS_STRUCT);
                assert!(matches!(members[0], TypeRef::Base { fc: FC_LONG, .. }));
                match &members[1] {
                    TypeRef::Pointer { pointee, .. } => {
                        assert!(matches!(**pointee, TypeRef::Str { wide: true, .. }));
                    }
                    other => panic!("expected pointer member, got {other:?}"),
                }
            }
            other => panic!("expected bogus struct, got {other:?}"),
        }
    }

    #[test]
    fn decodes_interface_pointer_iid() {
        match decode_type(&complex_type_fmt(), 76, 0) {
            TypeRef::InterfacePtr { iid, .. } => {
                assert_eq!(iid.as_deref(), Some("00000000-0000-0000-c000-000000000046"));
            }
            other => panic!("expected interface ptr, got {other:?}"),
        }
    }

    #[test]
    fn decodes_context_handle() {
        assert!(matches!(
            decode_type(&complex_type_fmt(), 98, 0),
            TypeRef::ContextHandle {
                ctx_flags: 0xa0,
                ..
            }
        ));
    }

    #[test]
    fn decodes_encapsulated_union() {
        match decode_type(&complex_type_fmt(), 110, 0) {
            TypeRef::Union {
                encapsulated,
                switch_fc,
                arms,
                ..
            } => {
                assert!(encapsulated);
                assert_eq!(switch_fc, FC_LONG);
                assert_eq!(arms.len(), 2);
                assert_eq!(arms[0].case_value, 1);
                assert!(matches!(*arms[0].ty, TypeRef::Base { fc: FC_LONG, .. }));
                assert_eq!(arms[1].case_value, 2);
                assert!(matches!(*arms[1].ty, TypeRef::Base { fc: FC_DOUBLE, .. }));
            }
            other => panic!("expected union, got {other:?}"),
        }
    }

    /// Exact TYPE format string from `samples/ndrcomplex2` (M2.2 types).
    fn complex2_type_fmt() -> Vec<u8> {
        vec![
            0x00, 0x00, // 0
            0x1c, 0x03, // 2: FC_CVARRAY
            0x04, 0x00, // 4: elem size 4
            0x28, 0x00, // 6: conformance (param FC_LONG)
            0x08, 0x00, // 8: conf offset = stack 8
            0x01, 0x00, // 10: conf flags
            0x28, 0x00, // 12: variance (param FC_LONG)
            0x10, 0x00, // 14: var offset = stack 16
            0x01, 0x00, // 16: var flags
            0x08, 0x5b, // 18: FC_LONG (element), FC_END
            0x11, 0x00, // 20: FC_RP
            0x14, 0x00, // 22: -> 42
            0x1c, 0x03, // 24: FC_CVARRAY (CVStruct.data)
            0x04, 0x00, // 26: elem size 4
            0x08, 0x00, // 28: conformance (field FC_LONG)
            0xfc, 0xff, // 30: -4
            0x01, 0x00, // 32: flags
            0x08, 0x00, // 34: variance (field FC_LONG)
            0xfc, 0xff, // 36: -4
            0x01, 0x00, // 38: flags
            0x08, 0x5b, // 40: FC_LONG (element), FC_END
            0x19, 0x03, // 42: FC_CVSTRUCT
            0x04, 0x00, // 44: fixed size 4
            0xea, 0xff, // 46: -22 -> 24 (the CVARRAY)
            0x08, 0x5b, // 48: FC_LONG, FC_END
            0x11, 0x00, // 50: FC_RP
            0x0e, 0x00, // 52: -> 66
            0x1b, 0x00, // 54: FC_CARRAY (Mip.data, byte)
            0x01, 0x00, // 56: elem size 1
            0x08, 0x00, // 58: conformance (field FC_LONG)
            0xfc, 0xff, // 60: -4
            0x01, 0x00, // 62: flags
            0x01, 0x5b, // 64: FC_BYTE (element), FC_END
            0x17, 0x03, // 66: FC_CSTRUCT (Mip)
            0x04, 0x00, // 68: fixed size 4
            0xf0, 0xff, // 70: -16 -> 54 (the CARRAY)
            0x08, 0x5b, // 72: FC_LONG, FC_END
            0x1a, 0x03, // 74: FC_BOGUS_STRUCT (BogusEl)
            0x10, 0x00, // 76: size 16
            0x00, 0x00, // 78: conf off 0
            0x06, 0x00, // 80: ptr layout -> 86
            0x08, 0x40, // 82: FC_LONG, FC_STRUCTPAD4
            0x36, 0x5b, // 84: FC_POINTER, FC_END
            0x12, 0x08, // 86: FC_UP [simple]
            0x25, 0x5c, // 88: FC_C_WSTRING, FC_PAD
            0x21, 0x03, // 90: FC_BOGUS_ARRAY
            0x00, 0x00, // 92: num elems 0
            0x28, 0x00, // 94: conformance (param FC_LONG)
            0x08, 0x00, // 96: conf offset = stack 8
            0x01, 0x00, // 98: conf flags
            0xff, 0xff, 0xff, 0xff, // 100: variance sentinel (-1)
            0x00, 0x00, // 104: variance flags
            0x4c, 0x00, // 106: FC_EMBEDDED_COMPLEX (element)
            0xde, 0xff, // 108: -34 -> 74 (BogusEl)
            0x5c, 0x5b, // 110: FC_PAD, FC_END
            0x11, 0x00, // 112: FC_RP
            0x02, 0x00, // 114: -> 116
            0x2b, 0x08, // 116: FC_NON_ENCAPSULATED_UNION, switch FC_LONG
            0x28, 0x00, // 118: switch_is corr (param FC_LONG)
            0x08, 0x00, // 120: switch offset = stack 8
            0x01, 0x00, // 122: corr flags
            0x02, 0x00, // 124: arms block -> 126
            0x08, 0x00, // 126: union size 8
            0x02, 0x00, // 128: 2 arms
            0x01, 0x00, 0x00, 0x00, // 130: case 1
            0x08, 0x80, // 134: arm FC_LONG
            0x02, 0x00, 0x00, 0x00, // 136: case 2
            0x0c, 0x80, // 140: arm FC_DOUBLE
            0x00, 0x00, // 142: default arm none
            0x00, // 144
        ]
    }

    #[test]
    fn decodes_conformant_varying_array() {
        // element must be FC_LONG at off+16 (not the variance descriptor).
        match decode_type(&complex2_type_fmt(), 2, 0) {
            TypeRef::Array {
                fc,
                element,
                conformance,
                ..
            } => {
                assert_eq!(fc, FC_CVARRAY);
                assert!(matches!(*element, TypeRef::Base { fc: FC_LONG, .. }));
                assert_eq!(conformance.unwrap().offset, 8);
            }
            other => panic!("expected cvarray, got {other:?}"),
        }
    }

    #[test]
    fn decodes_conformant_varying_struct() {
        match decode_type(&complex2_type_fmt(), 42, 0) {
            TypeRef::Struct { fc, members, .. } => {
                assert_eq!(fc, FC_CVSTRUCT);
                assert!(matches!(members[0], TypeRef::Base { fc: FC_LONG, .. }));
                // trailing member is the CVARRAY
                assert!(matches!(members[1], TypeRef::Array { fc: FC_CVARRAY, .. }));
            }
            other => panic!("expected cvstruct, got {other:?}"),
        }
    }

    #[test]
    fn decodes_conformant_byte_array_element() {
        // The MInterfacePointer shape: element must be FC_BYTE, not FC_ZERO.
        match decode_type(&complex2_type_fmt(), 54, 0) {
            TypeRef::Array { fc, element, .. } => {
                assert_eq!(fc, FC_CARRAY);
                assert!(matches!(*element, TypeRef::Base { fc: FC_BYTE, .. }));
            }
            other => panic!("expected carray, got {other:?}"),
        }
    }

    #[test]
    fn decodes_bogus_array_of_structs() {
        match decode_type(&complex2_type_fmt(), 90, 0) {
            TypeRef::Array { fc, element, .. } => {
                assert_eq!(fc, FC_BOGUS_ARRAY);
                // element is a BogusEl (bogus struct with a pointer member)
                assert!(matches!(
                    *element,
                    TypeRef::Struct {
                        fc: FC_BOGUS_STRUCT,
                        ..
                    }
                ));
            }
            other => panic!("expected bogus array, got {other:?}"),
        }
    }

    /// Exact TYPE format string from `samples/ndrmarshal` (M2.3 types).
    fn marshal_type_fmt() -> Vec<u8> {
        vec![
            0x00, 0x00, // 0
            0x12, 0x00, // 2: FC_UP
            0x0e, 0x00, // 4: -> 18
            0x1b, 0x01, // 6: FC_CARRAY (BSTR wire: counted short array)
            0x02, 0x00, // 8: elem size 2
            0x09, 0x00, // 10: conformance FC_ULONG (field)
            0xfc, 0xff, // 12: -4
            0x01, 0x00, // 14: flags
            0x06, 0x5b, // 16: FC_SHORT (element), FC_END
            0x17, 0x03, // 18: FC_CSTRUCT
            0x08, 0x00, // 20: size 8
            0xf0, 0xff, // 22: -16 -> 6
            0x08, 0x08, // 24: FC_LONG, FC_LONG
            0x5c, 0x5b, // 26: FC_PAD, FC_END
            0xb4, 0x83, // 28: FC_USER_MARSHAL, flags
            0x00, 0x00, // 30: routine index 0
            0x08, 0x00, // 32: mem_size 8
            0x00, 0x00, // 34: flags2
            0xde, 0xff, // 36: -34 -> 2 (wire type = FC_UP)
            0x1f, 0x03, // 38: FC_SMVARRAY
            0x80, 0x00, // 40: total size 128
            0x20, 0x00, // 42: num elements 32
            0x04, 0x00, // 44: elem size 4
            0x28, 0x00, // 46: variance (param FC_LONG) [length_is]
            0x08, 0x00, // 48: var offset = stack 8
            0x01, 0x00, // 50: var flags
            0x08, 0x5b, // 52: FC_LONG (element), FC_END
            0x00, // 54
        ]
    }

    #[test]
    fn decodes_user_marshal_bstr() {
        // BSTR: user-marshal whose wire type is FC_UP -> conformant short array.
        match decode_type(&marshal_type_fmt(), 28, 0) {
            TypeRef::UserMarshal { mem_size, wire, .. } => {
                assert_eq!(mem_size, 8);
                // BSTR wire = FC_UP -> FLAGGED_WORD_BLOB (a CSTRUCT holding the
                // conformant short array).
                match *wire {
                    TypeRef::Pointer { pointee, .. } => {
                        assert!(matches!(*pointee, TypeRef::Struct { fc: FC_CSTRUCT, .. }));
                    }
                    other => panic!("expected pointer wire type, got {other:?}"),
                }
            }
            other => panic!("expected user marshal, got {other:?}"),
        }
    }

    #[test]
    fn decodes_small_varying_array() {
        match decode_type(&marshal_type_fmt(), 38, 0) {
            TypeRef::Array {
                fc,
                element,
                conformance,
                ..
            } => {
                assert_eq!(fc, FC_SMVARRAY);
                assert!(matches!(*element, TypeRef::Base { fc: FC_LONG, .. }));
                assert_eq!(conformance.unwrap().offset, 8); // length_is param
            }
            other => panic!("expected smvarray, got {other:?}"),
        }
    }

    #[test]
    fn decodes_non_encapsulated_union() {
        match decode_type(&complex2_type_fmt(), 116, 0) {
            TypeRef::Union {
                encapsulated,
                switch_fc,
                arms,
                ..
            } => {
                assert!(!encapsulated);
                assert_eq!(switch_fc, FC_LONG);
                assert_eq!(arms.len(), 2);
                assert!(matches!(*arms[0].ty, TypeRef::Base { fc: FC_LONG, .. }));
                assert!(matches!(*arms[1].ty, TypeRef::Base { fc: FC_DOUBLE, .. }));
            }
            other => panic!("expected non-encap union, got {other:?}"),
        }
    }
}
