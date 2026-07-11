/* An RPC server hosted inside a DLL (like real vendor services:
 * host.exe -> LoadLibrary(SomethingRpcServer.dll) -> RunServer). Used to
 * validate the coverage fuzzer's DLL-module instrumentation (cov-fuzz --module).
 * Registers the NdrTest interface on ncalrpc:ndrtestdll. Contains the same
 * (deliberately vulnerable) VulnCopy handler via server_impl.c.
 *
 * Build: build_dllhost.cmd -> NdrTestSvc.dll (+ NdrTestHost.exe) */

#include <windows.h>
#include "NdrTest.h"
#include <stdio.h>

static RPC_STATUS RPC_ENTRY AllowAll(RPC_IF_HANDLE ifspec, void* ctx) {
    (void)ifspec; (void)ctx;
    return RPC_S_OK;
}

__declspec(dllexport) int RunServer(void) {
    RPC_STATUS st = RpcServerUseProtseqEp(
        (RPC_CSTR)"ncalrpc",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_CSTR)"ndrtestdll",
        NULL);
    if (st) return (int)st;

    st = RpcServerRegisterIfEx(
        NdrTestIf_v1_0_s_ifspec, NULL, NULL,
        0, RPC_C_LISTEN_MAX_CALLS_DEFAULT, AllowAll);
    if (st) return (int)st;

    st = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    return (int)st;
}
