"""Test the Binary Ninja plugin's annotation logic WITHOUT Binary Ninja.

Injects the fake `binaryninja` module (mock_binaryninja), imports the real
plugin, and runs its extract task against a fake BinaryView backed by the real
NdrTest.dll (decoded via the real ndr-core cdylib). Asserts that the plugin
would name the interface and rename/comment the recovered handler functions.

Run: python bn-plugin/test_plugin.py
Requires the built cdylib and samples/ndrtest/NdrTest.dll.
"""

import importlib.util
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)


def load_plugin_with_mock():
    """Inject the mock BN, then load the plugin's __init__.py as a module."""
    sys.path.insert(0, HERE)  # so `import ndr_ffi`/`ndr_render` fall-backs work
    import mock_binaryninja

    sys.modules["binaryninja"] = mock_binaryninja
    spec = importlib.util.spec_from_file_location(
        "ipc_dcom_ndr_plugin", os.path.join(HERE, "__init__.py")
    )
    plugin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(plugin)
    return plugin, mock_binaryninja


def main() -> int:
    target = os.path.join(REPO, "samples", "ndrtest", "NdrTest.dll")
    if not os.path.exists(target):
        print(f"missing {target}; build the corpus first")
        return 2

    plugin, mockbn = load_plugin_with_mock()

    # Two commands should have registered at import time.
    names = [n for (n, _d, _a) in mockbn.PluginCommand.registered]
    assert any("Extract" in n for n in names), names
    print(f"registered commands: {names}")

    # NdrTest.dll is x64, preferred image base 0x180000000.
    bv = mockbn.BinaryView(target, image_base=0x180000000)

    task = plugin.ExtractInterfacesTask(bv, rename=True)
    task.run()

    # One interface should have been named.
    assert len(bv.symbols) == 1, f"expected 1 interface symbol, got {bv.symbols}"
    iface_sym = next(iter(bv.symbols.values()))
    print(f"interface symbol: {iface_sym.name} @ {hex(iface_sym.address)}")
    assert iface_sym.name.startswith("RpcServerInterface_a1b2c3d4"), iface_sym.name

    # Five handlers should have been created + renamed + commented.
    assert len(bv.functions) == 5, f"expected 5 handlers, got {len(bv.functions)}"
    for addr, func in sorted(bv.functions.items()):
        assert func.name.startswith("Srv_a1b2c3d4_proc"), func.name
        assert func.comments, f"handler {func.name} has no signature comment"
        print(f"  {hex(addr)}  {func.name}  // {list(func.comments.values())[0]}")

    print("\nOK: plugin annotation logic verified against real decoded data.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
