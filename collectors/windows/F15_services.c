#include "collector.h"

/* Read-only SCM access. Pagination is bounded on XP as well as modern Windows.
 * Windows may silently omit services for which QUERY_STATUS is not granted. */
void collect_F15(void) {
    SC_HANDLE manager = OpenSCManagerW(NULL, NULL,
        SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    BYTE *page = NULL, *config = NULL;
    DWORD resume = 0, count = 0, error = 0, config_errors = 0;
    BOOL finished = FALSE;
    if (!manager) { error_result("scm_open_failed", GetLastError()); return; }
    page = (BYTE *)malloc(65536);
    config = (BYTE *)malloc(8192);
    if (!page || !config) {
        free(page); free(config); CloseServiceHandle(manager);
        error_result("service_memory_limit", 0); return;
    }
    add("{\"scope\":\"visible_win32_services\",\"visibility\":\"caller_permissions\",\"items\":[");
    for (unsigned pages = 0; pages < 32 && !stopping; pages++) {
        DWORD needed = 0, returned = 0, previous = resume;
        BOOL ok = EnumServicesStatusExW(manager, SC_ENUM_PROCESS_INFO,
            SERVICE_WIN32, SERVICE_STATE_ALL, page, 65536, &needed, &returned,
            &resume, NULL);
        error = ok ? 0 : GetLastError();
        if (!ok && error != ERROR_MORE_DATA) break;
        ENUM_SERVICE_STATUS_PROCESSW *rows = (ENUM_SERVICE_STATUS_PROCESSW *)page;
        DWORD i;
        for (i = 0; i < returned && count < 512 && used < CAP-65536 && !stopping; i++) {
            ENUM_SERVICE_STATUS_PROCESSW *row = &rows[i];
            SC_HANDLE service = OpenServiceW(manager, row->lpServiceName, SERVICE_QUERY_CONFIG);
            DWORD config_error = service ? 0 : GetLastError();
            if (service) {
                if (!QueryServiceConfigW(service, (QUERY_SERVICE_CONFIGW *)config, 8192, &needed))
                    config_error = GetLastError();
                CloseServiceHandle(service);
            }
            if (count++) add(",");
            add("{\"name\":"); wstr(row->lpServiceName);
            add(",\"display_name\":"); wstr(row->lpDisplayName);
            add(",\"state\":%lu,\"service_type\":%lu,\"pid\":",
                (unsigned long)row->ServiceStatusProcess.dwCurrentState,
                (unsigned long)row->ServiceStatusProcess.dwServiceType);
            DWORD state = row->ServiceStatusProcess.dwCurrentState;
            if (state == SERVICE_RUNNING || state == SERVICE_PAUSED ||
                state == SERVICE_PAUSE_PENDING || state == SERVICE_CONTINUE_PENDING)
                add("%lu", (unsigned long)row->ServiceStatusProcess.dwProcessId);
            else add("null");
            if (!config_error) {
                QUERY_SERVICE_CONFIGW *c = (QUERY_SERVICE_CONFIGW *)config;
                add(",\"start_type\":%lu,\"account\":", (unsigned long)c->dwStartType);
                wstr(c->lpServiceStartName);
                add(",\"binary_path\":"); wstr(c->lpBinaryPathName);
                add(",\"config_status\":\"complete\"");
            } else {
                config_errors++;
                add(",\"start_type\":null,\"account\":null,\"binary_path\":null,\"config_status\":\"unavailable\"");
            }
            add(",\"config_win32_error\":%lu}", (unsigned long)config_error);
            if (count % 16 == 0) Sleep(5);
        }
        if (i < returned) break;
        if (ok) { finished = TRUE; break; }
        /* Avoid spinning if the database changes without forward progress. */
        if (!returned || previous == resume) break;
    }
    add("],\"status\":\"%s\",\"count\":%lu,\"config_errors\":%lu,\"win32_error\":%lu}",
        finished && !config_errors && !stopping ? "complete" : "partial",
        (unsigned long)count, (unsigned long)config_errors, (unsigned long)error);
    free(page); free(config); CloseServiceHandle(manager);
}
