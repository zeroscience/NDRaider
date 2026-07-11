"""Shared ctypes binding to the ndr-core cdylib.

This is the single integration point with the Rust core. Both the standalone
test harness and the Binary Ninja plugin import from here so there is exactly
one place that knows the C ABI (mirroring the "one core, thin front-ends"
principle used on the Rust side).

The ABI is intentionally tiny (see crates/ndr-core/src/ffi.rs):
    char* ndr_analyze_path_json(const char* path)   # caller frees
    void  ndr_string_free(char*)
    const char* ndr_version()                        # static, do not free
"""

from __future__ import annotations

import ctypes
import json
import os
import sys
from typing import Any, Optional


def _default_library_name() -> str:
    if sys.platform == "win32":
        return "ndr_core.dll"
    if sys.platform == "darwin":
        return "libndr_core.dylib"
    return "libndr_core.so"


def _candidate_paths(explicit: Optional[str]) -> list[str]:
    """Places to look for the compiled cdylib, most specific first."""
    if explicit:
        return [explicit]
    name = _default_library_name()
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)  # bn-plugin/ -> repo root
    env = os.environ.get("NDR_CORE_LIB")
    cands = []
    if env:
        cands.append(env)
    cands += [
        os.path.join(repo, "target", "release", name),
        os.path.join(repo, "target", "debug", name),
        os.path.join(here, name),  # shipped alongside the plugin
    ]
    return cands


class NdrCore:
    """Thin wrapper around the loaded cdylib."""

    def __init__(self, lib_path: Optional[str] = None):
        path = next((p for p in _candidate_paths(lib_path) if os.path.exists(p)), None)
        if path is None:
            searched = "\n  ".join(_candidate_paths(lib_path))
            raise FileNotFoundError(
                "could not locate the ndr-core cdylib. Build it with "
                "`cargo build -p ndr-core` (or --release). Searched:\n  " + searched
            )
        self.path = path
        self._lib = ctypes.CDLL(path)

        self._lib.ndr_analyze_path_json.restype = ctypes.c_void_p
        self._lib.ndr_analyze_path_json.argtypes = [ctypes.c_char_p]
        self._lib.ndr_string_free.restype = None
        self._lib.ndr_string_free.argtypes = [ctypes.c_void_p]
        self._lib.ndr_version.restype = ctypes.c_char_p
        self._lib.ndr_version.argtypes = []

    def version(self) -> str:
        return self._lib.ndr_version().decode("utf-8")

    def analyze(self, pe_path: str) -> dict[str, Any]:
        """Analyze a PE file, returning the parsed report dict.

        Raises RuntimeError if the core returns NULL (bad path, parse failure).
        """
        raw = pe_path.encode("utf-8")
        ptr = self._lib.ndr_analyze_path_json(raw)
        if not ptr:
            raise RuntimeError(f"ndr-core failed to analyze {pe_path!r} (returned NULL)")
        try:
            text = ctypes.cast(ptr, ctypes.c_char_p).value or b""
            return json.loads(text.decode("utf-8"))
        finally:
            # Always hand the buffer back to Rust to free - freeing here (e.g.
            # with libc.free) would cross allocators and corrupt the heap.
            self._lib.ndr_string_free(ptr)
