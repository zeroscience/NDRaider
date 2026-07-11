"""Standalone FFI smoke test - validates the ctypes<->cdylib boundary without
Binary Ninja. Run: python bn-plugin/test_ffi.py [path-to-pe]

Defaults to the ground-truth NdrTest.dll if present.
"""

import os
import sys

from ndr_ffi import NdrCore


def main() -> int:
    core = NdrCore()
    print(f"loaded: {core.path}")
    print(f"ndr-core version: {core.version()}")

    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        here = os.path.dirname(os.path.abspath(__file__))
        repo = os.path.dirname(here)
        target = os.path.join(repo, "samples", "ndrtest", "NdrTest.dll")
        if not os.path.exists(target):
            print(f"no target given and {target} not found; build the corpus first")
            return 2

    report = core.analyze(target)
    ifaces = report.get("interfaces", [])
    arch = "x64" if report.get("is_64bit") else "x86"
    print(f"\ntarget: {report.get('target')}  ({arch})")
    print(f"interfaces: {len(ifaces)}")
    for ir in ifaces:
        procs = ir.get("procedures", [])
        # RpcInterface fields are flattened onto each interface entry.
        ver = ir.get("version", {})
        print(f"  {ir.get('uuid')} v{ver.get('major')}.{ver.get('minor')}"
              f"  procs={len(procs)}")
        for p in procs:
            print(f"     [{p['proc_num']}] {len(p['params'])} params")

    # Basic contract assertions so this doubles as a regression check.
    assert isinstance(ifaces, list), "interfaces must be a list"
    print("\nOK: FFI round-trip succeeded.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
