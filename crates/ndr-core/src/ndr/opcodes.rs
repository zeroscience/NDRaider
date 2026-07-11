//! NDR format-character (`FC_*`) constants and helpers.
//!
//! These are the opcodes of the little bytecode language MIDL emits to describe
//! every parameter and type. The values match Microsoft's `ndrtypes.h`. The M2
//! interpreter (see `super::interp`) walks procedure format strings one `FC_*`
//! byte at a time; this module is the shared vocabulary.
//!
//! Reference: [MS-RPCE] and the DCE/RPC NDR engine. Values are stable and have
//! been for decades, so hard-coding them is safe.

#![allow(dead_code)] // Many codes are defined for completeness ahead of M2 use.

// --- Simple / base types ------------------------------------------------
pub const FC_ZERO: u8 = 0x00;
pub const FC_BYTE: u8 = 0x01;
pub const FC_CHAR: u8 = 0x02;
pub const FC_SMALL: u8 = 0x03;
pub const FC_USMALL: u8 = 0x04;
pub const FC_WCHAR: u8 = 0x05;
pub const FC_SHORT: u8 = 0x06;
pub const FC_USHORT: u8 = 0x07;
pub const FC_LONG: u8 = 0x08;
pub const FC_ULONG: u8 = 0x09;
pub const FC_FLOAT: u8 = 0x0a;
pub const FC_HYPER: u8 = 0x0b;
pub const FC_DOUBLE: u8 = 0x0c;
pub const FC_ENUM16: u8 = 0x0d;
pub const FC_ENUM32: u8 = 0x0e;
pub const FC_IGNORE: u8 = 0x0f;
pub const FC_ERROR_STATUS_T: u8 = 0x10;

// --- Pointers -----------------------------------------------------------
pub const FC_RP: u8 = 0x11; // reference pointer
pub const FC_UP: u8 = 0x12; // unique pointer
pub const FC_OP: u8 = 0x13; // OLE unique pointer to object
pub const FC_FP: u8 = 0x14; // full pointer

// --- Structures ---------------------------------------------------------
pub const FC_STRUCT: u8 = 0x15; // simple struct
pub const FC_PSTRUCT: u8 = 0x16; // struct containing pointers
pub const FC_CSTRUCT: u8 = 0x17; // conformant struct
pub const FC_CPSTRUCT: u8 = 0x18; // conformant struct with pointers
pub const FC_CVSTRUCT: u8 = 0x19; // conformant varying struct
pub const FC_BOGUS_STRUCT: u8 = 0x1a; // complex struct

// --- Arrays -------------------------------------------------------------
pub const FC_CARRAY: u8 = 0x1b; // conformant array
pub const FC_CVARRAY: u8 = 0x1c; // conformant varying array
pub const FC_SMFARRAY: u8 = 0x1d; // small fixed array
pub const FC_LGFARRAY: u8 = 0x1e; // large fixed array
pub const FC_SMVARRAY: u8 = 0x1f; // small varying array
pub const FC_LGVARRAY: u8 = 0x20; // large varying array
pub const FC_BOGUS_ARRAY: u8 = 0x21; // complex array

// --- Strings ------------------------------------------------------------
pub const FC_C_CSTRING: u8 = 0x22; // conformant char string
pub const FC_C_BSTRING: u8 = 0x23;
pub const FC_C_SSTRING: u8 = 0x24; // conformant struct string
pub const FC_C_WSTRING: u8 = 0x25; // conformant wide string
pub const FC_CSTRING: u8 = 0x26; // non-conformant char string
pub const FC_BSTRING: u8 = 0x27;
pub const FC_SSTRING: u8 = 0x28;
pub const FC_WSTRING: u8 = 0x29; // non-conformant wide string

// --- Unions -------------------------------------------------------------
pub const FC_ENCAPSULATED_UNION: u8 = 0x2a;
pub const FC_NON_ENCAPSULATED_UNION: u8 = 0x2b;

pub const FC_BYTE_COUNT_POINTER: u8 = 0x2c;
pub const FC_TRANSMIT_AS: u8 = 0x2d;
pub const FC_REPRESENT_AS: u8 = 0x2e;
pub const FC_IP: u8 = 0x2f; // interface pointer

// --- Binding handles ----------------------------------------------------
pub const FC_BIND_CONTEXT: u8 = 0x30;
pub const FC_BIND_GENERIC: u8 = 0x31;
pub const FC_BIND_PRIMITIVE: u8 = 0x32;
pub const FC_AUTO_HANDLE: u8 = 0x33;
pub const FC_CALLBACK_HANDLE: u8 = 0x34;

pub const FC_UNUSED1: u8 = 0x35;
pub const FC_POINTER: u8 = 0x36;

// --- Alignment / padding ------------------------------------------------
pub const FC_ALIGNM2: u8 = 0x37;
pub const FC_ALIGNM4: u8 = 0x38;
pub const FC_ALIGNM8: u8 = 0x39;
pub const FC_UNUSED2: u8 = 0x3a;
pub const FC_UNUSED3: u8 = 0x3b;
pub const FC_UNUSED4: u8 = 0x3c;
pub const FC_STRUCTPAD1: u8 = 0x3d;
pub const FC_STRUCTPAD2: u8 = 0x3e;
pub const FC_STRUCTPAD3: u8 = 0x3f;
pub const FC_STRUCTPAD4: u8 = 0x40;
pub const FC_STRUCTPAD5: u8 = 0x41;
pub const FC_STRUCTPAD6: u8 = 0x42;
pub const FC_STRUCTPAD7: u8 = 0x43;

pub const FC_STRING_SIZED: u8 = 0x44;
pub const FC_UNUSED5: u8 = 0x45;

// --- Pointer-layout / repeat descriptors --------------------------------
pub const FC_NO_REPEAT: u8 = 0x46;
pub const FC_FIXED_REPEAT: u8 = 0x47;
pub const FC_VARIABLE_REPEAT: u8 = 0x48;
pub const FC_FIXED_OFFSET: u8 = 0x49;
pub const FC_VARIABLE_OFFSET: u8 = 0x4a;
pub const FC_PP: u8 = 0x4b; // pointer-layout block
pub const FC_EMBEDDED_COMPLEX: u8 = 0x4c;

// --- Parameter descriptors ----------------------------------------------
pub const FC_IN_PARAM: u8 = 0x4d;
pub const FC_IN_PARAM_BASETYPE: u8 = 0x4e;
pub const FC_IN_PARAM_NO_FREE_INST: u8 = 0x4f;
pub const FC_IN_OUT_PARAM: u8 = 0x50;
pub const FC_OUT_PARAM: u8 = 0x51;
pub const FC_RETURN_PARAM: u8 = 0x52;
pub const FC_RETURN_PARAM_BASETYPE: u8 = 0x53;

// --- Expression / correlation operators ---------------------------------
pub const FC_DEREFERENCE: u8 = 0x54;
pub const FC_DIV_2: u8 = 0x55;
pub const FC_MULT_2: u8 = 0x56;
pub const FC_ADD_1: u8 = 0x57;
pub const FC_SUB_1: u8 = 0x58;
pub const FC_CALLBACK: u8 = 0x59;
pub const FC_CONSTANT_IID: u8 = 0x5a;
pub const FC_END: u8 = 0x5b;
pub const FC_PAD: u8 = 0x5c;

// --- Notable high-range codes (NDR64-era / newer features) --------------
pub const FC_HARD_STRUCT: u8 = 0xb1;
pub const FC_TRANSMIT_AS_PTR: u8 = 0xb2;
pub const FC_REPRESENT_AS_PTR: u8 = 0xb3;
pub const FC_USER_MARSHAL: u8 = 0xb4;
pub const FC_PIPE: u8 = 0xb5;
pub const FC_SUPPLEMENT: u8 = 0xb6;
pub const FC_RANGE: u8 = 0xb7;
pub const FC_INT3264: u8 = 0xb8;
pub const FC_UINT3264: u8 = 0xb9;
pub const FC_END_OF_UNIVERSE: u8 = 0xba;

/// Human-readable name for a format character, for pseudo-IDL dumps and debug.
/// Returns `"FC_UNKNOWN"` for codes we don't have a name for.
pub fn fc_name(code: u8) -> &'static str {
    match code {
        FC_ZERO => "FC_ZERO",
        FC_BYTE => "FC_BYTE",
        FC_CHAR => "FC_CHAR",
        FC_SMALL => "FC_SMALL",
        FC_USMALL => "FC_USMALL",
        FC_WCHAR => "FC_WCHAR",
        FC_SHORT => "FC_SHORT",
        FC_USHORT => "FC_USHORT",
        FC_LONG => "FC_LONG",
        FC_ULONG => "FC_ULONG",
        FC_FLOAT => "FC_FLOAT",
        FC_HYPER => "FC_HYPER",
        FC_DOUBLE => "FC_DOUBLE",
        FC_ENUM16 => "FC_ENUM16",
        FC_ENUM32 => "FC_ENUM32",
        FC_IGNORE => "FC_IGNORE",
        FC_ERROR_STATUS_T => "FC_ERROR_STATUS_T",
        FC_RP => "FC_RP",
        FC_UP => "FC_UP",
        FC_OP => "FC_OP",
        FC_FP => "FC_FP",
        FC_STRUCT => "FC_STRUCT",
        FC_PSTRUCT => "FC_PSTRUCT",
        FC_CSTRUCT => "FC_CSTRUCT",
        FC_CPSTRUCT => "FC_CPSTRUCT",
        FC_CVSTRUCT => "FC_CVSTRUCT",
        FC_BOGUS_STRUCT => "FC_BOGUS_STRUCT",
        FC_CARRAY => "FC_CARRAY",
        FC_CVARRAY => "FC_CVARRAY",
        FC_SMFARRAY => "FC_SMFARRAY",
        FC_LGFARRAY => "FC_LGFARRAY",
        FC_SMVARRAY => "FC_SMVARRAY",
        FC_LGVARRAY => "FC_LGVARRAY",
        FC_BOGUS_ARRAY => "FC_BOGUS_ARRAY",
        FC_C_CSTRING => "FC_C_CSTRING",
        FC_C_BSTRING => "FC_C_BSTRING",
        FC_C_SSTRING => "FC_C_SSTRING",
        FC_C_WSTRING => "FC_C_WSTRING",
        FC_CSTRING => "FC_CSTRING",
        FC_BSTRING => "FC_BSTRING",
        FC_SSTRING => "FC_SSTRING",
        FC_WSTRING => "FC_WSTRING",
        FC_ENCAPSULATED_UNION => "FC_ENCAPSULATED_UNION",
        FC_NON_ENCAPSULATED_UNION => "FC_NON_ENCAPSULATED_UNION",
        FC_BYTE_COUNT_POINTER => "FC_BYTE_COUNT_POINTER",
        FC_TRANSMIT_AS => "FC_TRANSMIT_AS",
        FC_REPRESENT_AS => "FC_REPRESENT_AS",
        FC_IP => "FC_IP",
        FC_BIND_CONTEXT => "FC_BIND_CONTEXT",
        FC_BIND_GENERIC => "FC_BIND_GENERIC",
        FC_BIND_PRIMITIVE => "FC_BIND_PRIMITIVE",
        FC_AUTO_HANDLE => "FC_AUTO_HANDLE",
        FC_CALLBACK_HANDLE => "FC_CALLBACK_HANDLE",
        FC_POINTER => "FC_POINTER",
        FC_ALIGNM2 => "FC_ALIGNM2",
        FC_ALIGNM4 => "FC_ALIGNM4",
        FC_ALIGNM8 => "FC_ALIGNM8",
        FC_STRUCTPAD1 => "FC_STRUCTPAD1",
        FC_STRUCTPAD2 => "FC_STRUCTPAD2",
        FC_STRUCTPAD3 => "FC_STRUCTPAD3",
        FC_STRUCTPAD4 => "FC_STRUCTPAD4",
        FC_STRUCTPAD5 => "FC_STRUCTPAD5",
        FC_STRUCTPAD6 => "FC_STRUCTPAD6",
        FC_STRUCTPAD7 => "FC_STRUCTPAD7",
        FC_STRING_SIZED => "FC_STRING_SIZED",
        FC_NO_REPEAT => "FC_NO_REPEAT",
        FC_FIXED_REPEAT => "FC_FIXED_REPEAT",
        FC_VARIABLE_REPEAT => "FC_VARIABLE_REPEAT",
        FC_FIXED_OFFSET => "FC_FIXED_OFFSET",
        FC_VARIABLE_OFFSET => "FC_VARIABLE_OFFSET",
        FC_PP => "FC_PP",
        FC_EMBEDDED_COMPLEX => "FC_EMBEDDED_COMPLEX",
        FC_IN_PARAM => "FC_IN_PARAM",
        FC_IN_PARAM_BASETYPE => "FC_IN_PARAM_BASETYPE",
        FC_IN_PARAM_NO_FREE_INST => "FC_IN_PARAM_NO_FREE_INST",
        FC_IN_OUT_PARAM => "FC_IN_OUT_PARAM",
        FC_OUT_PARAM => "FC_OUT_PARAM",
        FC_RETURN_PARAM => "FC_RETURN_PARAM",
        FC_RETURN_PARAM_BASETYPE => "FC_RETURN_PARAM_BASETYPE",
        FC_DEREFERENCE => "FC_DEREFERENCE",
        FC_DIV_2 => "FC_DIV_2",
        FC_MULT_2 => "FC_MULT_2",
        FC_ADD_1 => "FC_ADD_1",
        FC_SUB_1 => "FC_SUB_1",
        FC_CALLBACK => "FC_CALLBACK",
        FC_CONSTANT_IID => "FC_CONSTANT_IID",
        FC_END => "FC_END",
        FC_PAD => "FC_PAD",
        FC_HARD_STRUCT => "FC_HARD_STRUCT",
        FC_TRANSMIT_AS_PTR => "FC_TRANSMIT_AS_PTR",
        FC_REPRESENT_AS_PTR => "FC_REPRESENT_AS_PTR",
        FC_USER_MARSHAL => "FC_USER_MARSHAL",
        FC_PIPE => "FC_PIPE",
        FC_SUPPLEMENT => "FC_SUPPLEMENT",
        FC_RANGE => "FC_RANGE",
        FC_INT3264 => "FC_INT3264",
        FC_UINT3264 => "FC_UINT3264",
        FC_END_OF_UNIVERSE => "FC_END_OF_UNIVERSE",
        _ => "FC_UNKNOWN",
    }
}

/// Wire size in bytes of a simple/base type, if `code` is one. `None` for
/// non-simple codes (pointers, structs, arrays, ...), whose size depends on
/// context the interpreter must resolve. `FC_INT3264`/`FC_UINT3264` are
/// platform-dependent and returned as `None` here (resolved with pointer width
/// by the caller).
pub fn simple_type_size(code: u8) -> Option<u8> {
    Some(match code {
        FC_BYTE | FC_CHAR | FC_SMALL | FC_USMALL => 1,
        FC_WCHAR | FC_SHORT | FC_USHORT | FC_ENUM16 => 2,
        FC_LONG | FC_ULONG | FC_FLOAT | FC_ENUM32 | FC_ERROR_STATUS_T => 4,
        FC_HYPER | FC_DOUBLE => 8,
        _ => return None,
    })
}

/// Is this the start of a pointer format?
pub fn is_pointer(code: u8) -> bool {
    matches!(code, FC_RP | FC_UP | FC_OP | FC_FP)
}
