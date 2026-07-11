/* Trivial server-method implementations so the MIDL server stub (NdrTest_s.c)
 * links into a real DLL. Bodies are irrelevant - we only need the server-side
 * NDR structures (MIDL_SERVER_INFO, dispatch table, format strings) present in
 * a genuine PE for the extractor to walk. Prototypes come from NdrTest.h. */

#include <windows.h>
#include "NdrTest.h"
#include <stdio.h>
#include <string.h>

/* Diagnostic: prove whether fuzz calls actually reach the manager routines. */
static void logcall(const char* fn) {
    FILE* f = fopen("server_calls.log", "a");
    if (f) { fprintf(f, "%s\n", fn); fclose(f); }
}

long AddNumbers(handle_t h, long a, short b, small c, double d, byte e) {
    (void)h; (void)b; (void)c; (void)d; (void)e;
    logcall("AddNumbers");
    return a;
}

void SendPoint(handle_t h, Point* p) {
    (void)h; (void)p;
}

long SumArray(handle_t h, long count, long data[]) {
    (void)h; (void)data;
    return count;
}

void Echo(handle_t h, wchar_t* msg) {
    (void)h; (void)msg;
}

void GetValue(handle_t h, long* value) {
    (void)h;
    logcall("GetValue");
    if (value) *value = 0;
}

/* DELIBERATELY VULNERABLE - test target only. Classic unchecked copy of an
 * attacker-controlled size_is buffer into a fixed stack buffer. len > 64
 * overruns `buf`, corrupting the /GS cookie -> STATUS_STACK_BUFFER_OVERRUN on
 * return, which the coverage fuzzer's debugger catches. Never do this for real. */
#pragma optimize("", off)
void VulnCopy(handle_t h, long len, byte data[]) {
    (void)h;
    char buf[64];
    logcall("VulnCopy");
    if (len > 0 && data) {
        memcpy(buf, data, (size_t)len);   /* <-- no bounds check: overflow */
    }
    /* Touch buf so the copy isn't elided. */
    { volatile char sink = buf[0]; (void)sink; }
}
#pragma optimize("", on)
