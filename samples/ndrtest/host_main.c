/* Tiny host process: loads the RPC-server DLL and runs it - mirrors how real
 * vendor services host their interface in a *RpcServer.dll. The coverage fuzzer
 * spawns this and instruments NdrTestSvc.dll (cov-fuzz --module NdrTestSvc.dll).
 *
 * Build: build_dllhost.cmd -> NdrTestHost.exe */

#include <windows.h>
#include <stdio.h>

typedef int (*RunServerFn)(void);

int main(void) {
    HMODULE h = LoadLibraryA("NdrTestSvc.dll");
    if (!h) {
        printf("LoadLibrary(NdrTestSvc.dll) failed: %lu\n", GetLastError());
        return 1;
    }
    RunServerFn run = (RunServerFn)GetProcAddress(h, "RunServer");
    if (!run) {
        printf("GetProcAddress(RunServer) failed\n");
        return 1;
    }
    printf("NdrTestHost: loaded NdrTestSvc.dll -> ncalrpc:ndrtestdll\n");
    fflush(stdout);
    return run(); /* blocks in RpcServerListen */
}
