# Binary Ninja plugin (M3)

Decodes RPC/DCOM interfaces via the `ndr-core` cdylib and annotates the
BinaryView - it does **not** reimplement the NDR parser.

## Files
- `ndr_ffi.py` - ctypes binding to the cdylib (the one integration point).
- `ndr_render.py` - pure JSON→signature rendering (mirrors the Rust CLI).
- `__init__.py` - registers the Binary Ninja commands.
- `plugin.json` - plugin-manager manifest.
- `test_ffi.py`, `test_render.py` - standalone checks that run **without**
  Binary Ninja (validate the FFI boundary and the renderer against the
  ground-truth `samples/ndrtest/NdrTest.dll`).

## Setup
1. Build the core library:
   ```
   cargo build -p ndr-core --release
   ```
   This produces `target/release/ndr_core.dll` (or `.so`/`.dylib`).
2. Make the library discoverable by the plugin (any one of):
   - leave it under `target/release` (the plugin searches the repo), or
   - set `NDR_CORE_LIB=/full/path/to/ndr_core.dll`, or
   - copy it next to this plugin in Binary Ninja's `plugins/` directory.
3. Symlink or copy this `bn-plugin/` folder into Binary Ninja's user plugins
   directory (rename it to something import-safe, e.g. `ipc_dcom_ndr`).

## Usage
Open a PE (RPC/DCOM server DLL/EXE) in Binary Ninja, then from the command
palette / Plugins menu:
- **NDR ▸ Extract RPC-DCOM interfaces (rename handlers)** - names each
  `RPC_SERVER_INTERFACE`, and renames + comments the server handler functions
  recovered from the dispatch table (`Srv_<uuid>_procN`, with the decoded
  signature as a comment).
- **NDR ▸ Annotate RPC-DCOM interfaces (comment only)** - same, without
  renaming functions.

## What it uses from ndr-core
The JSON report includes, per interface: `uuid`, `version`, `struct_rva`, and
per procedure the decoded `params` plus `routine_rva` (the handler's address in
the dispatch table) - which is what makes handler renaming possible.

## Binary Ninja edition note
Plugins/scripting require **Personal** edition or higher - Binary Ninja **Free
disables the plugin API entirely**, so this plugin cannot run there. Everything
below verifies the plugin's logic *without* a BN license.

## Verify without Binary Ninja
```
cargo build -p ndr-core
python bn-plugin/test_ffi.py       # FFI round-trip (ctypes -> cdylib)
python bn-plugin/test_render.py    # signature renderer vs. ground truth
python bn-plugin/test_plugin.py    # FULL plugin via a mock `binaryninja` module
```
`test_plugin.py` injects `mock_binaryninja.py` (a fake BN that records API
calls), imports the real plugin, and runs its extract task against a fake
`BinaryView` backed by the real `NdrTest.dll` (decoded through the real
cdylib). It asserts the plugin names the interface and renames/comments all
five handler functions - i.e. the exact BN API calls it would make, validated
end-to-end with no license.
