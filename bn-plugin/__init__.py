"""IPC-DCOM-Fuzzer - Binary Ninja plugin.

Extracts RPC/DCOM interfaces and NDR-decoded method signatures from the current
binary by calling the ndr-core cdylib (see ndr_ffi.py), then annotates the
BinaryView: names each RPC_SERVER_INTERFACE, and renames + comments the decoded
server handler functions.

All heavy lifting lives in the Rust core; this file is glue + BN API calls.
"""

from __future__ import annotations

import binaryninja as bn
from binaryninja import BackgroundTaskThread, PluginCommand
from binaryninja import Symbol, SymbolType

# Work both as a Binary Ninja package (relative import) and standalone - the
# latter lets the mock-BN test harness (test_plugin.py) exercise this file
# without a Binary Ninja license.
try:
    from .ndr_ffi import NdrCore
    from .ndr_render import render_proc_signature
except ImportError:  # pragma: no cover - only when run outside a package
    from ndr_ffi import NdrCore
    from ndr_render import render_proc_signature


def _short_uuid(uuid: str) -> str:
    """First group of a UUID - enough to disambiguate in a symbol name."""
    return uuid.split("-", 1)[0]


def _rva_to_addr(bv: "bn.BinaryView", rva: int) -> int:
    """Map an ndr-core RVA to a BinaryView address.

    RVAs are relative to the image base; a mapped PE's `bv.start` is that base.
    """
    return bv.start + rva


class ExtractInterfacesTask(BackgroundTaskThread):
    def __init__(self, bv: "bn.BinaryView", rename: bool = True):
        super().__init__("Extracting RPC/DCOM interfaces…", can_cancel=True)
        self.bv = bv
        self.rename = rename

    def run(self) -> None:
        bv = self.bv
        path = bv.file.original_filename or bv.file.filename
        if not path:
            bn.log_error("[ndr] BinaryView has no backing file path")
            return

        try:
            core = NdrCore()
        except FileNotFoundError as e:
            bn.log_error(f"[ndr] {e}")
            return

        bn.log_info(f"[ndr] core {core.version()} analyzing {path}")
        try:
            report = core.analyze(path)
        except RuntimeError as e:
            bn.log_error(f"[ndr] analysis failed: {e}")
            return

        interfaces = report.get("interfaces", [])
        bn.log_info(f"[ndr] {len(interfaces)} candidate interface(s)")

        n_named_ifaces = 0
        n_named_funcs = 0
        for ir in interfaces:
            if self.cancelled:
                break
            uuid = ir.get("uuid", "unknown")
            ver = ir.get("version", {})
            vstr = f"{ver.get('major', 0)}_{ver.get('minor', 0)}"

            # 1) Name + comment the interface structure.
            iaddr = _rva_to_addr(bv, ir.get("struct_rva", 0))
            sym_name = f"RpcServerInterface_{_short_uuid(uuid)}_v{vstr}"
            try:
                bv.define_user_symbol(Symbol(SymbolType.DataSymbol, iaddr, sym_name))
                bv.set_comment_at(iaddr, f"RPC interface {uuid} v{ver.get('major',0)}.{ver.get('minor',0)}")
                n_named_ifaces += 1
            except Exception as e:  # noqa: BLE001 - BN can throw various types
                bn.log_warn(f"[ndr] could not annotate interface @ {hex(iaddr)}: {e}")

            # 2) Rename + comment each decoded handler function.
            for proc in ir.get("procedures", []):
                sig = render_proc_signature(proc)
                rrva = proc.get("routine_rva")
                if rrva is None:
                    continue
                faddr = _rva_to_addr(bv, rrva)
                func = bv.get_function_at(faddr)
                if func is None:
                    bv.add_function(faddr)
                    func = bv.get_function_at(faddr)
                if func is None:
                    continue
                func.set_comment_at(faddr, sig)
                if self.rename:
                    fname = f"Srv_{_short_uuid(uuid)}_proc{proc.get('proc_num')}"
                    try:
                        func.name = fname
                        n_named_funcs += 1
                    except Exception as e:  # noqa: BLE001
                        bn.log_warn(f"[ndr] rename failed @ {hex(faddr)}: {e}")

            bn.log_info(f"[ndr]   {uuid} v{ver.get('major',0)}.{ver.get('minor',0)} "
                        f"- {len(ir.get('procedures', []))} method(s)")

        bn.log_info(f"[ndr] done: named {n_named_ifaces} interface(s), "
                    f"{n_named_funcs} handler(s)")


def _run_extract(bv: "bn.BinaryView") -> None:
    ExtractInterfacesTask(bv, rename=True).start()


def _run_annotate_only(bv: "bn.BinaryView") -> None:
    ExtractInterfacesTask(bv, rename=False).start()


PluginCommand.register(
    "NDR\\Extract RPC-DCOM interfaces (rename handlers)",
    "Decode NDR interfaces via ndr-core and rename + comment server handlers.",
    _run_extract,
)
PluginCommand.register(
    "NDR\\Annotate RPC-DCOM interfaces (comment only)",
    "Same as extract, but only add comments - do not rename functions.",
    _run_annotate_only,
)
