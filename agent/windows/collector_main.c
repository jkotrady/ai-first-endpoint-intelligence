/* Experimental standalone collector. One compile-time entrypoint, no ID dispatch. */
#include "collector.h"
#include "catalog_generated.h"
#ifndef COLLECTOR_ENTRY
#error COLLECTOR_ENTRY must be selected by the verified catalog build
#endif
void COLLECTOR_ENTRY(void);
static BOOL WINAPI on_signal(DWORD signal) {
    (void)signal; InterlockedExchange(&stopping,1); return TRUE;
}
int main(int argc,char **argv) {
    WSADATA wd;
    if(argc==2 && !strcmp(argv[1],"--version")) {puts(AGENT_SOURCE_SHA256);return 0;}
    if(argc!=1) {fputs("This collector takes no arguments. --version prints its source fingerprint.\n",stderr);return 2;}
    SetConsoleCtrlHandler(on_signal,TRUE);
    SetPriorityClass(GetCurrentProcess(),BELOW_NORMAL_PRIORITY_CLASS);
    if(WSAStartup(MAKEWORD(2,2),&wd))return 1;
    used=0;overflow=0;COLLECTOR_ENTRY();
    if(overflow)error_result("output_limit",0);
    puts(output);WSACleanup();
    return strstr(output,"\"status\":\"error\"")?2:0;
}
