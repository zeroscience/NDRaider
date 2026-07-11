# Screenshots for the README

Drop images here with these filenames and reference them from the
[README](../../README.md) with `![...](docs/img/<file>.png)` tags (the banner slot
at the top of the README is already stubbed out). Suggested captures:

| Filename | What to capture |
|----------|-----------------|
| `banner.png` | (optional) project banner/logo for the README top |
| `scan-rpcss.png` | `ndr-cli scan C:\Windows\System32\rpcss.dll` - the interface + method list |
| `grammar-json.png` | a slice of `ndr-cli grammar ... --compact` (or piped through a JSON pretty-printer), highlighting an `array` node's `length.from = param` |
| `gen-hex.png` | `ndr-fuzz gen NdrTest.dll --opnum 2 --count 6 --seed 42` - hex buffers; circle a consistent vs. a desynced case |
| `live-fuzz.png` | `ndr-fuzz ... --auth --i-am-authorized` output (`sent/responses/faults`) next to the server log |
| `list.png` | `ndr-fuzz list <target>` |
| `sweep-nonms.png` | the non-Microsoft table from a system-wide `ndr-cli sweep` cross-referenced with Authenticode signers (vendor / interface count / binary) |
| `alpc-ctx-fuzz.png` | `ndr-fuzz campaign ... --alpc ...` per-opnum tally with `(ctx)` markers + status codes - ideally before vs after context-handle chaining |
| `cov-fuzz-crash.png` | `ndr-fuzz cov-fuzz ...` run: "instrumented N blocks", coverage climbing, and the `!!! CRASH CAUGHT` line with the reproducer path |
| `bn-plugin.png` | Binary Ninja before/after: a `sub_...` handler renamed + commented |

Tips:
- A dark terminal theme reads well on GitHub.
- For the desync shot, `--seed 42` is reproducible - the same buffers every run.
- Crop tight; keep text legible at GitHub's rendered width.
