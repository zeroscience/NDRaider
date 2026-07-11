/* Minimal support so the MIDL client stub links into a real DLL.
 *
 * We don't need a functioning RPC client - we only need the RPC_CLIENT_INTERFACE
 * and the NDR format strings to be present in a genuine PE image that our
 * scanner can read. These stubs satisfy the linker's references. */

#include <windows.h>
#include <rpc.h>
#include <stdlib.h>

void __RPC_FAR* __RPC_USER MIDL_user_allocate(size_t size) {
    return malloc(size);
}

void __RPC_USER MIDL_user_free(void __RPC_FAR* p) {
    free(p);
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    (void)hinst; (void)reason; (void)reserved;
    return TRUE;
}
