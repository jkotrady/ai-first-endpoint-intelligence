#include "collector.h"

void collect_F04(void) {
  HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0); PROCESSENTRY32W pe; unsigned count=0;BOOL more;
  if(snap==INVALID_HANDLE_VALUE){error_result("snapshot_failed",GetLastError());return;}
  memset(&pe,0,sizeof(pe));pe.dwSize=sizeof(pe);more=Process32FirstW(snap,&pe);
  if(!more && GetLastError()!=ERROR_NO_MORE_FILES){DWORD e=GetLastError();CloseHandle(snap);error_result("process_enumeration_failed",e);return;}
  add("{\"items\":[");
  while(more && count<512 && used<CAP-4096 && !stopping) {
   if(count++) { add(","); }
   add("{\"pid\":%lu,\"parent_pid\":%lu,\"name\":",(unsigned long)pe.th32ProcessID,(unsigned long)pe.th32ParentProcessID);wstr(pe.szExeFile);add("}");
   more=Process32NextW(snap,&pe); if(count%32==0)Sleep(5);
  }
  DWORD err=more?0:GetLastError();CloseHandle(snap);
  add("],\"status\":\"%s\",\"count\":%u,\"win32_error\":%lu}",more||stopping||err!=ERROR_NO_MORE_FILES?"partial":"complete",count,(unsigned long)(err==ERROR_NO_MORE_FILES?0:err));

}
