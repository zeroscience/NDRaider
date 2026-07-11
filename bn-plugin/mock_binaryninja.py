"""A minimal fake `binaryninja` module for testing the plugin without a license.

Binary Ninja Free disables plugins/scripting, and CI has no BN at all. This
shim provides just enough of the BN API surface that the plugin imports and
calls, while *recording* every annotation so a test can assert the plugin did
the right thing against real ndr-core output.

Usage (see test_plugin.py):
    import sys, mock_binaryninja
    sys.modules["binaryninja"] = mock_binaryninja
    import __init__ as plugin   # now imports the mock
"""

from __future__ import annotations


# --- logging -------------------------------------------------------------
def log_info(msg):
    print(f"[info] {msg}")


def log_warn(msg):
    print(f"[warn] {msg}")


def log_error(msg):
    print(f"[error] {msg}")


# --- symbols -------------------------------------------------------------
class SymbolType:
    DataSymbol = "DataSymbol"
    FunctionSymbol = "FunctionSymbol"


class Symbol:
    def __init__(self, sym_type, addr, name):
        self.type = sym_type
        self.address = addr
        self.name = name


# --- plugin command registration ----------------------------------------
class PluginCommand:
    registered = []

    @classmethod
    def register(cls, name, description, action):
        cls.registered.append((name, description, action))


# --- background task base ------------------------------------------------
class BackgroundTaskThread:
    def __init__(self, initial_text="", can_cancel=False):
        self.initial_text = initial_text
        self.can_cancel = can_cancel
        self.cancelled = False

    def start(self):
        # Tests call .run() directly; start() runs synchronously here.
        self.run()


# --- fake Function / BinaryView (recording) ------------------------------
class FakeFunction:
    def __init__(self, addr):
        self.start = addr
        self.name = f"sub_{addr:x}"
        self.comments = {}

    def set_comment_at(self, addr, text):
        self.comments[addr] = text


class FakeFile:
    def __init__(self, path):
        self.original_filename = path
        self.filename = path


class BinaryView:
    """Just enough of a BinaryView to drive the plugin and record its actions."""

    def __init__(self, path, image_base):
        self.file = FakeFile(path)
        self.start = image_base
        self.symbols = {}      # addr -> Symbol
        self.comments = {}     # addr -> str
        self.functions = {}    # addr -> FakeFunction

    def define_user_symbol(self, sym):
        self.symbols[sym.address] = sym

    def set_comment_at(self, addr, text):
        self.comments[addr] = text

    def get_function_at(self, addr):
        return self.functions.get(addr)

    def add_function(self, addr):
        self.functions[addr] = FakeFunction(addr)
