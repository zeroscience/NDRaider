# Contributing to NDRaider

Thanks for your interest! This project decodes and fuzzes Windows RPC/DCOM, so
contributions tend to be either **NDR interpreter coverage** (decoding more
format-string opcodes) or **fuzzer/transport** features. Both are very welcome.

## Ground rules

- Be respectful; assume good faith.
- This is an **offensive security research tool**. Contributions must not add
  functionality whose *only* purpose is to attack third parties (mass targeting,
  self-propagation, etc.). See [`SECURITY.md`](SECURITY.md).
- By contributing, you agree your work is licensed under the project's dual
  **MIT OR Apache-2.0** license.

## Getting set up

```sh
# Rust toolchain (stable): https://rustup.rs
git clone https://github.com/zeroscience/NDRaider
cd NDRaider
cargo build
cargo test
```

To (re)build the local test corpus and server you also need the **Windows SDK**
(`midl`) and **VS Build Tools** (`cl`):

```sh
samples\ndrtest\build.cmd          # MIDL stubs + NdrTest.dll
samples\ndrtest\build_server.cmd   # local RPC server for live tests
```

## The golden rule: validate against ground truth

The NDR interpreter is the heart of the project, and it's easy to get a byte
offset subtly wrong. **Every change to NDR decoding must be validated against a
MIDL-compiled ground-truth sample**, not guessed against opaque system DLLs.

The workflow (this is how the whole interpreter was built):

1. Write a minimal `.idl` under `samples/` that exercises the feature.
2. Compile it with `midl` to get the generated `*_s.c` - that file's
   format-string byte arrays (with MIDL's comments) are your **oracle**.
3. Add a unit test in `crates/ndr-core/src/ndr/interp.rs` that feeds the exact
   oracle bytes to `decode_type` and asserts the decoded shape.
4. Only then point it at real binaries.

`docs/NDR_NOTES.md` documents the verified struct layouts and opcode semantics;
please keep it updated when you learn something new.

## Coding style

- Format with `rustfmt` (`cargo fmt`).
- `cargo clippy` should be clean (or explain any `#[allow]`).
- Match the surrounding code: comment the *why* for non-obvious NDR/RPC details,
  keep decoding defensive (bounds-checked, never panics on hostile input).
- Prefer small, focused PRs. One feature/opcode/transport per PR is ideal.

## Tests

- `cargo test` must pass. Add tests for new decoding (see the golden rule above)
  and for new pure logic (marshaling, mutation, PDU construction).
- For anything touching the live transport/auth, validate against the local
  `NdrTestServer` where feasible and describe what you ran in the PR.

## Good first contributions

See the roadmap in the [README](README.md#roadmap). Approachable items:

- Additional MIDL corpus cases + interpreter coverage for remaining opcodes
  (`FC_HARD_STRUCT`, `FC_BYTE_COUNT_POINTER`, expression conformance…).
- PKT_PRIVACY sealed requests (the buffer layout mirrors the working
  PKT_INTEGRITY path in `crates/ndr-fuzz/src/auth.rs`).
- `ncalrpc` (ALPC) or endpoint-mapper enumeration.
- Docs, examples, and README screenshots (`docs/img/`).

## Submitting a PR

1. Fork and branch (`feature/short-description`).
2. `cargo fmt && cargo clippy && cargo test`.
3. Open the PR with a clear description: what, why, and how you validated it.

## Found a 0day with NDRaider?

Awesome - that's exactly what it's for. Two small asks:

- **Disclose responsibly** to the affected vendor first (see [`SECURITY.md`](SECURITY.md)).
- **Give a shout-out.** If NDRaider helped you find or triage a bug, please credit
  the tool and its makers - **Silly Security Inc.** (<https://sillysec.com>) and
  **Zero Science Lab** (<https://zeroscience.mk>) - in your advisory / write-up /
  CVE acknowledgements. We'd also love to hear about it (open an issue or drop us a
  line) so we can link your finding from the README.

Thanks for helping map (and harden) the RPC surface.
