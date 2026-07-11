/* Minimal RPC server that hosts the NdrTest interface over ncacn_ip_tcp on
 * localhost, so the fuzzer (ndr-fuzz --target 127.0.0.1:49152) has a SAFE,
 * self-contained target to validate the live transport against - never point
 * the fuzzer at real system services.
 *
 * Build: build_server.cmd  ->  NdrTestServer.exe */

#include <windows.h>
#include "NdrTest.h"
#include <stdio.h>

/* Allow all callers. Registering ANY security callback also exempts this
 * interface from the "restrict unauthenticated RPC clients" policy, so our
 * raw (unauthenticated) fuzzer can actually reach the stub. This is a LOCAL
 * TEST server only. */
static RPC_STATUS RPC_ENTRY AllowAll(RPC_IF_HANDLE ifspec, void* ctx) {
    (void)ifspec; (void)ctx;
    return RPC_S_OK;
}

int main(void) {
    RPC_STATUS st;

    st = RpcServerUseProtseqEp(
        (RPC_CSTR)"ncacn_ip_tcp",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_CSTR)"49152",
        NULL);
    if (st) { printf("RpcServerUseProtseqEp(tcp) failed: %ld\n", st); return 1; }

    /* Local named pipe endpoint: not a "remote client", so unauthenticated
     * local calls reach the stub (unlike ncacn_ip_tcp). */
    st = RpcServerUseProtseqEp(
        (RPC_CSTR)"ncacn_np",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_CSTR)"\\pipe\\ndrtest",
        NULL);
    if (st) { printf("RpcServerUseProtseqEp(np) failed: %ld\n", st); return 1; }

    /* Local ALPC (ncalrpc) endpoint -> ALPC port \RPC Control\ndrtestalpc.
     * This is the transport the ndr-fuzz LRPC/ALPC code targets. */
    st = RpcServerUseProtseqEp(
        (RPC_CSTR)"ncalrpc",
        RPC_C_PROTSEQ_MAX_REQS_DEFAULT,
        (RPC_CSTR)"ndrtestalpc",
        NULL);
    if (st) { printf("RpcServerUseProtseqEp(ncalrpc) failed: %ld\n", st); return 1; }

    st = RpcServerRegisterIfEx(
        NdrTestIf_v1_0_s_ifspec, NULL, NULL,
        0, RPC_C_LISTEN_MAX_CALLS_DEFAULT, AllowAll);
    if (st) { printf("RpcServerRegisterIfEx failed: %ld\n", st); return 1; }

    /* Advertise NTLM so authenticated clients can bind (our raw fuzzer uses
     * NTLM via SSPI). Without this the server NAKs auth binds with
     * "authentication_type_not_recognized". */
    st = RpcServerRegisterAuthInfo(NULL, RPC_C_AUTHN_WINNT, NULL, NULL);
    if (st) { printf("RpcServerRegisterAuthInfo failed: %ld\n", st); return 1; }

    printf("NdrTest server: ncacn_ip_tcp:49152, ncacn_np:\\pipe\\ndrtest, "
           "ncalrpc:ndrtestalpc\n");
    fflush(stdout);

    st = RpcServerListen(1, RPC_C_LISTEN_MAX_CALLS_DEFAULT, FALSE);
    printf("RpcServerListen returned: %ld\n", st);
    return 0;
}
