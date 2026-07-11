"""Validate ndr_render against real ndr-core output for the ground-truth DLL.

Run: python bn-plugin/test_render.py
Requires the built cdylib and samples/ndrtest/NdrTest.dll.
"""

import os
import sys

from ndr_ffi import NdrCore
from ndr_render import render_proc_signature


def main() -> int:
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(here)
    target = os.path.join(repo, "samples", "ndrtest", "NdrTest.dll")
    if not os.path.exists(target):
        print(f"missing {target}; build the corpus first")
        return 2

    report = NdrCore().analyze(target)
    procs = report["interfaces"][0]["procedures"]
    sigs = [render_proc_signature(p) for p in procs]
    for s in sigs:
        print(" ", s)

    # NdrTest.idl ground truth (handle param is not an NDR arg, so omitted):
    #   AddNumbers(long,short,small,double,byte)->long
    #   SendPoint(Point*)          Point = {long,long}
    #   SumArray(long,long[])->long
    #   Echo(wchar*)
    #   GetValue([out] long*)
    assert "long proc0(" in sigs[0] and "double" in sigs[0], sigs[0]
    assert "struct{long,long}" in sigs[1], sigs[1]
    assert "size_is@" in sigs[2], sigs[2]
    assert "wchar" in sigs[3], sigs[3]
    assert "[out]" in sigs[4], sigs[4]
    print("\nOK: renderer matches ground truth.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
