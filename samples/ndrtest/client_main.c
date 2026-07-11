/* Known-good RPC client: uses the Windows RPC runtime + MIDL client stub to call
 * the NdrTest server with NTLM auth at CONNECT level - the same auth ndr-fuzz
 * attempts by hand. If this reaches the server handler (server_calls.log grows)
 * but ndr-fuzz does not, the server is fine and the bug is in ndr-fuzz's raw
 * PDU/auth framing. Also a reference to packet-capture and diff against ndr-fuzz.
 *
 * Build: build_client.cmd  ->  NdrTestClient.exe
 * Usage: NdrTestClient.exe [np|tcp]   (default np) */

#include <windows.h>
#include "NdrTest.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    RPC_STATUS st;
    RPC_WSTR binding = NULL;
    handle_t h = NULL;
    int use_tcp = (argc > 1 && strcmp(argv[1], "tcp") == 0);
    /* optional tcp port (argv[2]) so we can route through a capture proxy */
    wchar_t port[16] = L"49152";
    if (use_tcp && argc > 2) {
        MultiByteToWideChar(CP_ACP, 0, argv[2], -1, port, 16);
    }

    if (use_tcp) {
        st = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_ip_tcp",
                                      (RPC_WSTR)L"127.0.0.1", (RPC_WSTR)port,
                                      NULL, &binding);
    } else {
        st = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncacn_np",
                                      (RPC_WSTR)L".", (RPC_WSTR)L"\\pipe\\ndrtest",
                                      NULL, &binding);
    }
    if (st) { printf("StringBindingCompose failed: %ld\n", st); return 1; }

    st = RpcBindingFromStringBindingW(binding, &h);
    if (st) { printf("BindingFromStringBinding failed: %ld\n", st); return 1; }

    /* Same auth as ndr-fuzz attempts: NTLM (WINNT) at CONNECT level, default creds. */
    st = RpcBindingSetAuthInfoW(h, NULL, RPC_C_AUTHN_LEVEL_CONNECT,
                                RPC_C_AUTHN_WINNT, NULL, RPC_C_AUTHZ_NONE);
    if (st) { printf("BindingSetAuthInfo failed: %ld\n", st); return 1; }

    RpcTryExcept {
        long r = AddNumbers(h, 5, 2, 1, 3.0, 4);
        printf("AddNumbers(5,...) returned %ld  -- handler reached OK\n", r);
        long v = 0;
        GetValue(h, &v);
        printf("GetValue returned value=%ld\n", v);
    }
    RpcExcept(1) {
        printf("RPC call FAULTED: exception %lu\n", RpcExceptionCode());
    }
    RpcEndExcept

    RpcStringFreeW(&binding);
    RpcBindingFree(&h);
    return 0;
}
