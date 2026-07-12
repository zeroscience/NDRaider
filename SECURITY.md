# Security Policy

## About this project

NDRaider is an **offensive security research tool** for Windows RPC/DCOM. It is
intended for:

- authorized penetration testing,
- security research on systems you own or control,
- CTFs and educational use, and
- defensive analysis of your own services.

It is **not** intended for, and must not be used for, attacking systems you do
not own or lack explicit written authorization to test. Sending generated
requests is malformed-by-design and can crash the target service or destabilize
the host. You are solely responsible for how you use it.

## Reporting a vulnerability **in NDRaider itself**

If you find a security issue in this project's code (for example, memory unsafety
in the parser, or a way the tool could harm the operator's own machine), please
report it privately - do **not** open a public issue.

Preferred channels:

1. **GitHub private vulnerability reporting** - open a draft advisory via the
   repository's *Security → Report a vulnerability* tab.
2. Or email the maintainer at **`lab@zeroscience.mk`**.

Please include:

- a description of the issue and its impact,
- steps or a proof-of-concept to reproduce, and
- any suggested remediation.

We aim to acknowledge reports within a few days and to coordinate a fix and
disclosure timeline with you.

## Bugs you find *with* NDRaider (in third-party software)

If you use NDRaider to find a vulnerability in someone else's product, that is
**not** a vulnerability in this project - please do **not** report it here.
Instead:

- Only test software you are authorized to test.
- Disclose responsibly to the **affected vendor** (or via a recognized
  coordinated-disclosure program), giving them reasonable time to fix it.
- Do not include third-party 0-day details in this repo's issues or PRs.

## Supported versions

This is early-stage research software; only the latest `main` is supported.
Pin a commit if you need reproducibility.
