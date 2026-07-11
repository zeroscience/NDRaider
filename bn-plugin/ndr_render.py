"""Render decoded NDR types/procedures to human-readable signatures.

Pure functions over the JSON produced by ndr-core - no Binary Ninja dependency,
so this is unit-testable on its own. Mirrors the Rust CLI's renderer.
"""

from __future__ import annotations

from typing import Any


def _base_name(fc_name: str) -> str:
    return fc_name.replace("FC_", "").lower()


def render_type(t: dict[str, Any]) -> str:
    kind = t.get("kind")
    if kind == "base":
        return _base_name(t["name"])
    if kind == "str":
        return "wchar*" if t.get("wide") else "char*"
    if kind == "pointer":
        return render_type(t["pointee"]) + "*"
    if kind == "struct":
        inner = ",".join(render_type(m) for m in t.get("members", []))
        return f"struct{{{inner}}}(sz {t.get('size', 0)})"
    if kind == "array":
        conf = t.get("conformance")
        if conf is not None:
            # field-relative (signed) vs param stack offset, per raw_type nibble
            if conf.get("raw_type", 0) & 0xF0 == 0:
                off = conf.get("offset", 0)
                off = off - 0x10000 if off >= 0x8000 else off  # to signed i16
                n = f"size_is@{off}"
            else:
                n = f"size_is@{hex(conf.get('offset', 0))}"
        else:
            n = "[]"
        return f"{render_type(t['element'])}[{n}]"
    if kind == "fixed_array":
        return f"{render_type(t['element'])}[{t.get('total_size', 0)}]"
    if kind == "range":
        return f"{_base_name(t['base_name'])}[{t['min']}..{t['max']}]"
    if kind == "interface_ptr":
        iid = t.get("iid")
        return f"iface<{iid}>*" if iid else "iface*"
    if kind == "context_handle":
        return "ctx_handle"
    if kind == "union":
        prefix = "union" if t.get("encapsulated") else "union_ne"
        arms = "|".join(f"{a['case_value']}:{render_type(a['ty'])}" for a in t.get("arms", []))
        return f"{prefix}{{{arms}}}"
    if kind == "unresolved":
        return t.get("name", "FC_UNKNOWN")
    return "?"


def render_param(p: dict[str, Any]) -> str:
    dir_map = {"in": "in", "out": "out", "in_out": "in,out", "return": "ret"}
    d = dir_map.get(p.get("dir", "in"), "in")
    ty = p.get("ty", {})
    # simple-ref adds an implicit top-level pointer, but string/pointer types
    # already render one.
    implicit_ptr = p.get("simple_ref") and ty.get("kind") not in ("str", "pointer")
    star = "*" if implicit_ptr else ""
    return f"[{d}] {render_type(ty)}{star}"


def render_proc_signature(proc: dict[str, Any]) -> str:
    """A C-ish one-line signature for a decoded procedure."""
    params = proc.get("params", [])
    args = ", ".join(render_param(p) for p in params if p.get("dir") != "return")
    ret = next((render_type(p["ty"]) for p in params if p.get("dir") == "return"), "void")
    return f"{ret} proc{proc.get('proc_num', '?')}({args})"
