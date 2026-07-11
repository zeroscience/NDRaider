# RPC auth investigation - root cause (M5.3)

**Goal:** get `ndr-fuzz`'s raw DCE/RPC client to reach a server handler so fuzz
requests actually execute (not just bind).

**Symptom:** authenticated NTLM bind is accepted, but every REQUEST faults with
`status 0x00000005` (ACCESS_DENIED) and the handler is never invoked - even a
method with zero `[in]` params (so it isn't an NDR marshaling problem).

## How it was isolated

1. **Known-good reference client** (`client_main.c` → `NdrTestClient.exe`) uses
   the Windows RPC runtime + MIDL stub with the *same* auth params
   (`RpcBindingSetAuthInfoW(..., RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_AUTHN_WINNT)`).
   It **reaches the handler** (`server_calls.log` shows `AddNumbers`/`GetValue`).
   → The server is fine; the bug is entirely in `ndr-fuzz`'s wire framing.

2. **TCP capture proxy** (`rpc_proxy.py`, listens :49153 → forwards :49152) dumps
   each client→server PDU. We captured both clients and diffed.

## The captured difference (client → server PDUs)

**Runtime (works):**
```
BIND         auth_len=54   sec_trailer auth_level=0x02 (CONNECT) + NTLM negotiate
AUTH3        auth_len=88   auth_level=0x02              + NTLM authenticate
ALTER_CONTEXT auth_len=54  auth_level=0x05 (PKT_PRIVACY) ctx_id=1 + NTLM negotiate
AUTH3        auth_len=88   auth_level=0x05
REQUEST      auth_len=16   auth_level=0x05, auth_pad=0x0f, stub SEALED + 16-byte NTLM MAC
```

**ndr-fuzz (denied):**
```
BIND         auth_len=54   auth_level=0x02 + NTLM negotiate     (matches runtime)
AUTH3        auth_len=88   auth_level=0x02                      (matches runtime)
REQUEST      auth_len=0    plaintext stub, NO auth trailer      <-- rejected
```

## Root cause

The server (like most Windows RPC endpoints) effectively **requires
`RPC_C_AUTHN_LEVEL_PKT_PRIVACY` (0x05)**. The runtime silently upgrades a
requested `CONNECT` level to PKT_PRIVACY via an **ALTER_CONTEXT** and then
**seals (encrypts) every request** with a trailing 16-byte NTLM MAC.
`ndr-fuzz` sends `CONNECT`-level, *plaintext*, trailer-less requests → the
server denies them before dispatch. The 16-byte alignment fix from the earlier
advice is correct/spec-compliant but insufficient on its own.

## What's needed to finish (M5.4)

Implement PKT_PRIVACY in the raw client:
1. Establish the security context with `ISC_REQ_CONFIDENTIALITY |
   ISC_REQ_INTEGRITY` and negotiate `auth_level = 0x05` (try a direct
   PKT_PRIVACY bind first; add ALTER_CONTEXT only if the direct bind is NAK'd).
2. Per REQUEST: `EncryptMessage` (SSPI) to seal the stub data in place, append
   the `sec_trailer` + the 16-byte signature as the auth trailer, set
   `auth_length = 16`, and set `auth_pad_length` for the stub's 16-byte
   alignment. Responses are likewise sealed and must be `DecryptMessage`'d.
3. Maintain the per-PDU sequence number SSPI expects.

## M5.4 status - PKT_INTEGRITY implemented; handlers reached (with one caveat)

Implemented in `ndr-fuzz`: bind directly at `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY`
(0x05), 3-leg NTLM handshake, and per-request signing (`auth.rs::sign_request`)
that appends the 16-byte NTLM MAC. Sec_trailer is 4-byte aligned (matches the
capture); the request stub is padded to a 16-byte multiple on the wire.

**Working:** methods with **no `[in]` params** now authenticate and **reach the
handler** - e.g. `opnum 4` (GetValue): `sent=8 responses=8 faults=0`, and
`server_calls.log` shows 8 `GetValue` executions. The full pipeline
(handshake → sign → dispatch → response) is proven.

**SOLVED - fully working.** The fix: the **auth pad bytes must be inside the
signed `SECBUFFER_DATA` buffer** (stub + pad), signed with `MakeSignature`. The
earlier failure was a combination miss - I had tried padded-DATA only with
`EncryptMessage`, and `MakeSignature` only with *unpadded* DATA, never the
correct pairing. Empty-stub validated by luck (little/no DATA to get wrong).

Final recipe (`auth.rs::sign_request` + `dcerpc::build_request_signed`):
```
SecBuffer[0] = SECBUFFER_DATA | READONLY_WITH_CHECKSUM  // common + request header
SecBuffer[1] = SECBUFFER_DATA                           // stub data + auth pad
SecBuffer[2] = SECBUFFER_DATA | READONLY_WITH_CHECKSUM  // sec_trailer (8 bytes)
SecBuffer[3] = SECBUFFER_TOKEN                          // 16-byte NTLM MAC
MakeSignature(ctx, 0, &desc, seq)   // seq starts at 0; handshake consumes none
```

**Result:** all methods authenticate and reach handlers. Fuzzing `NdrTestServer`:
opnums 0/1/3/4 → all responses; opnum 2 (`SumArray`, `size_is`) → responses for
consistent lengths and **NDR faults for the desynced-length mutations** - the
structure-aware fuzzer stressing the unmarshaler exactly as intended.

## Reproduce
```
samples\ndrtest\build.cmd          # MIDL stubs
samples\ndrtest\build_server.cmd   # NdrTestServer.exe (tcp 49152 + \pipe\ndrtest)
samples\ndrtest\build_client.cmd   # NdrTestClient.exe (known-good reference)
python samples\ndrtest\rpc_proxy.py runtime cap_runtime.txt   # then run a client
NdrTestClient.exe tcp 49153        # capture the runtime's PDUs
ndr-fuzz gen ...\NdrTest.dll --opnum 0 --target 127.0.0.1:49153 --auth --i-am-authorized
```
