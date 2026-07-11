# NDR / MIDL internals notes

Working reference for the extractor. Everything here is what the MIDL compiler
emits into a stub binary; recovering it statically is the whole point of the
project. Field offsets below are for the classic (non-NDR64) `-Oicf` interpreter
layout unless noted.

## 1. The scan anchor: transfer syntax GUIDs

We locate interfaces (M1) by scanning `.rdata` for the fixed transfer-syntax
GUID that MIDL bakes into every `RPC_*_INTERFACE`:

| Syntax | GUID | Version | LE byte pattern (first 4) |
|--------|------|---------|---------------------------|
| NDR (DCE) | `8a885d04-1ceb-11c9-9fe8-08002b104860` | 2.0 | `04 5d 88 8a` |
| NDR64     | `71710533-beba-4937-8319-b5dbef9ccc36` | 1.0 | `33 05 71 71` |

The version dword immediately after the GUID (`2,0` or `1,0`) is a cheap,
high-signal confirmation that we're inside a real header and not loose data.

## 2. RPC_SERVER_INTERFACE / RPC_CLIENT_INTERFACE

Both share the same leading layout. Offsets relative to struct start:

```
+0x00  ULONG                  Length            // sizeof(struct): 0x44 x86, 0x60 x64
+0x04  RPC_SYNTAX_IDENTIFIER  InterfaceId       // <-- the interface's own UUID+ver
+0x18  RPC_SYNTAX_IDENTIFIER  TransferSyntax    // <-- NDR/NDR64 GUID (our anchor)
+0x2c  PRPC_DISPATCH_TABLE    DispatchTable
+0x30  ...                    (protseq endpoints, reserved)
       const void            *InterpreterInfo   // -> MIDL_SERVER_INFO (server side)
       ULONG                  Flags
```

```
RPC_SYNTAX_IDENTIFIER  = GUID (16 bytes) + RPC_VERSION (u16 major, u16 minor)  => 20 bytes
```

So from a transfer-GUID hit at file offset `o`:
- `InterfaceId.SyntaxGUID`    = `o - 20`
- `InterfaceId.SyntaxVersion` = `o - 4`
- `Length`                    = `o - 24`
- `TransferSyntax.Version`    = `o + 16`

This is exactly what `interface.rs` implements.

> Note: pointer fields (`DispatchTable`, `InterpreterInfo`) are native width, so
> the offsets of everything past `TransferSyntax` differ between x86 and x64.
> M2 must branch on `PeImage::is_64bit` when walking past the fixed prefix.

## 3. The pointer chain into the format strings (M2)

```
RPC_SERVER_INTERFACE.InterpreterInfo
  -> MIDL_SERVER_INFO {
       const MIDL_STUB_DESC *pStubDesc;
       const SERVER_ROUTINE *DispatchTable;
       const unsigned char  *ProcString;        // concatenated proc format strings
       const unsigned short *FmtStringOffset;    // [proc_num] -> offset into ProcString
       ...
     }
  MIDL_STUB_DESC {
       void                 *RpcInterfaceInformation;   // -> back to RPC_*_INTERFACE
       ...
       const unsigned char  *pFormatTypes;              // the TYPE format string
       ...
       unsigned long         MIDLVersion;
  }
```

- **Proc format string** - one entry per method: an `Oi2` header
  (flags, stack size, number of params, ...) followed by param descriptors.
- **Type format string** - the recursive type graph; complex params carry a
  `u16` offset into this string.

Method count comes from `RPC_DISPATCH_TABLE.DispatchTableCount` (the
`DispatchTable` field of the interface struct points at it).

### Verified field offsets (from the `samples/ndrtest` oracle)

All confirmed against MIDL 8.01 output, `target_arch=AMD64`, `Oicf` + robust.
`ptr` = native pointer (8 bytes x64 / 4 bytes x86). Pointer slots on disk hold
`image_base + RVA` (preferred base); subtract `image_base` to get an RVA.

`RPC_SERVER_INTERFACE` (Length `0x60` x64 / `0x44` x86):
| field | x64 off | x86 off |
|-------|--------:|--------:|
| Length (u32) | 0x00 | 0x00 |
| InterfaceId (GUID+ver, 20) | 0x04 | 0x04 |
| TransferSyntax (GUID+ver, 20) | 0x18 | 0x18 |
| *(pad to ptr align)* | 0x2c | - |
| DispatchTable (ptr → RPC_DISPATCH_TABLE) | 0x30 | 0x2c |
| RpcProtseqEndpointCount (u32) | 0x38 | 0x30 |
| RpcProtseqEndpoint (ptr) | 0x40 | 0x34 |
| DefaultManagerEpv (ptr) | 0x48 | 0x38 |
| **InterpreterInfo** (ptr → MIDL_SERVER_INFO) | **0x50** | **0x3c** |
| Flags (u32) | 0x58 | 0x40 |

`RPC_DISPATCH_TABLE`: `DispatchTableCount` (u32) at +0x00 → **method count**.

`MIDL_SERVER_INFO`:
| field | x64 off | x86 off |
|-------|--------:|--------:|
| pStubDesc (ptr → MIDL_STUB_DESC) | 0x00 | 0x00 |
| DispatchTable / SERVER_ROUTINE[] (ptr) | 0x08 | 0x04 |
| **ProcString** (ptr → proc format string) | 0x10 | 0x08 |
| **FmtStringOffset** (ptr → u16[method_count]) | 0x18 | 0x0c |

`MIDL_STUB_DESC`:
| field | x64 off | x86 off |
|-------|--------:|--------:|
| RpcInterfaceInformation (ptr) | 0x00 | 0x00 |
| pfnAllocate / pfnFree (ptr,ptr) | 0x08 | 0x04 |
| *(handle info + 5 routine-table ptrs)* | 0x18 | 0x0c |
| **pFormatTypes** (ptr → type format string) | **0x40** | **0x20** |

Walk: interface struct → `+InterpreterInfo` → `MIDL_SERVER_INFO` →
`{ProcString, FmtStringOffset, pStubDesc}`; `pStubDesc+pFormatTypes` = type
string base; `DispatchTable→count`. Per proc `i`: `ProcString[FmtStringOffset[i]]`.

## 4. Proc format string (Oicf) - verified against the oracle

Each proc entry begins with a header, then one 6-byte descriptor per parameter.

### Proc header (explicit primitive handle case)
```
+0  u8   handle_type (0 = explicit handle present)
+1  u8   Oi flags (old interface flags)              e.g. 0x48
+2  u32  rpc_flags
+6  u16  proc_num
+8  u16  stack_size
    -- explicit primitive handle descriptor (present when byte0 == 0 handle) --
+10 u8   FC_BIND_PRIMITIVE (0x32)
+11 u8   handle flags
+12 u16  handle stack offset
    -- Oi2 (interpreter) descriptor --
+14 u16  constant_client_buffer_size
+16 u16  constant_server_buffer_size
+18 u8   Oi2 flags   (bit 0x40 = HasExtensions, 0x02 = HasReturn, 0x01 = ClientMustSize...)
+19 u8   number_of_params
    -- extension block, present when Oi2 flags & HasExtensions --
+20 u8   ext_size (bytes, e.g. 0x0a)
+21 u8   ext_flags
+22 u16  ClientCorrHint
+24 u16  ServerCorrHint
+26 u16  NotifyIndex
+28 u16  (x64 only) FloatDoubleArgMask
```
The header length varies (implicit vs explicit handle, extensions present or
not). The safe cursor after the header = header_start + fixed_prefix + handle
desc + Oi2 + ext_size. `number_of_params` bounds the descriptor loop.

### Parameter descriptor - 6 bytes (`NDR_PARAM_OIF`)
```
+0  u16  PARAM_ATTRIBUTES (LE bitfield, see below)
+2  u16  StackOffset  (arg offset on the RPC stack)
+4  if IsBasetype:  u8 FORMAT_CHARACTER + u8 FC_PAD   (inline simple type)
    else:           u16 TypeOffset                    (offset into TYPE fmt string)
```

`PARAM_ATTRIBUTES` bits (confirmed from oracle comments):
| bit | name | meaning |
|-----|------|---------|
| 0x0001 | MustSize | client must size |
| 0x0002 | MustFree | |
| 0x0008 | IsIn | `[in]` |
| 0x0010 | IsOut | `[out]` |
| 0x0020 | IsReturn | return value |
| 0x0040 | IsBasetype | byte+4 is an FC, not a type offset |
| 0x0080 | IsByValue | |
| 0x0100 | IsSimpleRef | top-level `*` handled by ref |
| 0xe000 | ServerAllocSize | (value>>13)*8 bytes |

`ParamDir` in `ndr/mod.rs` maps from IsIn/IsOut/IsReturn.

Worked example - `AddNumbers` param `a`: attrs `0x48` (IsIn|IsBasetype),
stack `0x08`, FC `0x08` = FC_LONG. `SendPoint` param `p`: attrs `0x10a`
(MustFree|IsIn|IsSimpleRef), stack `0x08`, TypeOffset `0x06` → FC_STRUCT (Point).

## 4b. Complex type layouts (M2.1) - verified against `samples/ndrcomplex`

Offsets relative to the type's first byte. Validated against MIDL output.

- **FC_SMFARRAY** `1d` / **FC_LGFARRAY** `1e`: `[FC][align][size][element…][FC_END]`
  where `size` is `u16` (SM) or `u32` (LG); element at +4 (SM) / +6 (LG).
- **FC_RANGE** `b7`: `[FC][base_fc][i32 min][i32 max]` (12 bytes).
- **FC_IP** `2f`: interface pointer. If next byte is `FC_CONSTANT_IID` `5a`,
  a 16-byte IID follows inline; else the IID is an `iid_is` param at runtime.
- **FC_BIND_CONTEXT** `30`: `[FC][ctx_flags][rundown_index][ordinal]` (4 bytes).
- **FC_CSTRUCT** `17` / **FC_CPSTRUCT** `18`: `[FC][align][u16 fixed_size]`
  `[i16 →array_desc][fixed members…][FC_END]`. Array offset is relative to +4.
- **FC_BOGUS_STRUCT** `1a`: `[FC][align][u16 size][u16 conf_off][u16 →ptr_layout]`
  `[members…][FC_END]`. Each `FC_POINTER` `36` placeholder in the member stream
  consumes the next 4-byte pointer descriptor from the pointer-layout block.
- **FC_ENCAPSULATED_UNION** `2a`: `[FC][switch_byte][u16 size][u16 n_arms]`
  then per-arm `[i32 case][u16 arm_type]`, then `[u16 default_arm]`. An arm word
  with bit `0x8000` set is an inline simple `FC_*` (low byte); otherwise it is a
  signed offset (from the arm word) to a complex type.
- **Correlation descriptor** (in CARRAY etc.): `[type][reserved][u16 offset]`
  `[u16 flags]`. `type` high nibble 0 = field-relative (signed) offset;
  nibble 2 = top-level (param stack) offset. Low nibble = the count's `FC_*`.

### M2.2 additions - verified against `samples/ndrcomplex2`
- **FC_CVARRAY** `1c` (conformant *varying* array): `[FC][align][u16 elem_size]`
  `[conformance 6][variance 6][element…][FC_END]` - element at **off+16**.
- **FC_CVSTRUCT** `19`: identical layout to FC_CSTRUCT (points at a CVARRAY).
- **FC_BOGUS_ARRAY** `21` (conformant case): `[FC][align][u16 num_elems]`
  `[conformance 6][variance 6][element…][FC_END]` - element at **off+16**; the
  element is typically an `FC_EMBEDDED_COMPLEX` redirect.
- **FC_NON_ENCAPSULATED_UNION** `2b`: `[FC][switch_fc][switch_is corr 6]`
  `[u16 →arms_block]`, arms block = `[u16 size][u16 n_arms][arms…]`.
- **FC_EMBEDDED_COMPLEX** `4c` as a standalone redirect: `[FC][reserved]`
  `[i16 →real type]` - now followed transparently in `decode_type`.
- **FC_INT3264/FC_UINT3264**: platform ints, wired as 4 bytes under classic NDR.

### The `FC_ZERO` diagnosis - CORRECTED (expression conformance, not robustness)
Earlier hypothesis (non-robust 4-byte correlation) was **wrong**: MIDL refuses
`/no_robust` on x64 (`warning MIDL2469`), so x64 stubs are *always* robust.

The real cause, confirmed by dumping raw bytes (`ndr-cli dump-types`): some
arrays use a **variable-length, expression-based conformance descriptor**. In
rpcss interface 0 the `FC_BOGUS_ARRAY` at type-offset 66 has its element
(`FC_UP`) at offset **102** - 36 bytes into the type, not the fixed 16 our
`off+16` assumption expects. Bytes 70–101 encode `size_is((size+1)&~1)` - the
`ORPC_EXTENT_ARRAY` expression conformance (DCE `FC_EXPR_*` opcodes). Because we
can't traverse the expression, `off+16` lands on a `0x00` pad → `FC_ZERO`.

combase → 0 because its interfaces don't use the expression-conformance extent
pattern; rpcss/spoolsv ORPCTHIS/ORPCTHAT plumbing does. **Fuzz value is low** -
these are DCOM extent arrays, not method-specific params - so full expression
conformance parsing is deferred. We now label the unresolved element honestly
rather than emitting a misleading `FC_ZERO` base type.

### Still deferred (long tail - need oracles)
- **M2.3**: non-robust correlation descriptors (the `FC_ZERO` fix above).
- **FC_USER_MARSHAL** `b4` (BSTR/HWND/custom wire types), **FC_SMVARRAY** `1f`
  / **FC_LGVARRAY** `20` (fixed varying arrays), **FC_HARD_STRUCT** `b1`,
  **FC_BYTE_COUNT_POINTER** `2c`, **FC_SUPPLEMENT** `b6`. All rendered as named
  `Unresolved` - never a crash.

## 5. Validation plan (before trusting real system DLLs)

Ground-truth against binaries **we** compile, where the answer is known:

1. Author minimal `.idl` files exercising one feature each (scalars, a struct,
   a conformant array, a pointer, a union, a string).
2. Compile with the Windows SDK MIDL compiler to produce `*_s.c`/`*_c.c` stubs;
   build them into a small DLL. Keep the generated `*_p.c`/format-string source
   as the human-readable oracle.
3. Run `ndr-cli scan` and diff recovered UUID/version/param layout against the
   MIDL-generated source.
4. Only once the synthetic corpus passes, point it at real targets
   (`rpcrt4.dll` consumers: spooler, DCOM services, etc.).

Corpus lives under `samples/` (git-ignored - do not commit SDK output or system
binaries).

## References

- [MS-RPCE]: Remote Procedure Call Protocol Extensions
- DCE 1.1 RPC (NDR transfer syntax)
- ndrtypes.h (`FC_*` values) - Windows SDK
- Prior art: RpcView, OleViewDotNet / NtApiDotNet NDR parser (dynamic)
