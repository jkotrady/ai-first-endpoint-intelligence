#include "collector.h"

void collect_F01(void) {
  WCHAR computer[256]; DWORD size=256; MEMORYSTATUSEX mem; SYSTEM_INFO si; OSVERSIONINFOEXW os;
  typedef LONG (WINAPI *VersionFn)(OSVERSIONINFOEXW *); VersionFn version=(VersionFn)(void*)GetProcAddress(GetModuleHandleA("ntdll.dll"),"RtlGetVersion");
  memset(&os,0,sizeof(os));os.dwOSVersionInfoSize=sizeof(os);
  if(!version || version(&os)!=0 || !GetComputerNameW(computer,&size)) {error_result("identity_unavailable",GetLastError());return;}
  memset(&mem,0,sizeof(mem));mem.dwLength=sizeof(mem); if(!GlobalMemoryStatusEx(&mem)){error_result("memory_unavailable",GetLastError());return;}
  GetSystemInfo(&si);
  add("{\"status\":\"complete\",\"hostname\":");wstr(computer);
  add(",\"os\":\"Windows %lu.%lu build %lu SP%u\",\"agent_arch\":\"x86\",\"logical_processors\":%lu,\"ram_total_bytes\":%llu,\"ram_free_bytes\":%llu",
   (unsigned long)os.dwMajorVersion,(unsigned long)os.dwMinorVersion,(unsigned long)os.dwBuildNumber,os.wServicePackMajor,(unsigned long)si.dwNumberOfProcessors,(unsigned long long)mem.ullTotalPhys,(unsigned long long)mem.ullAvailPhys);
  ULONG bytes=0;DWORD network=GetAdaptersInfo(NULL,&bytes);IP_ADAPTER_INFO *adapters=NULL;
  if(network==ERROR_BUFFER_OVERFLOW && bytes<=CAP) {
   adapters=(IP_ADAPTER_INFO*)malloc(bytes);
   if(!adapters){error_result("adapter_memory_limit",0);return;}
   network=GetAdaptersInfo(adapters,&bytes);
  }
  if(network!=NO_ERROR && network!=ERROR_NO_DATA){free(adapters);error_result("adapter_enumeration_failed",network);return;}
  add(",\"ipv4\":[");unsigned addresses=0;
  for(IP_ADAPTER_INFO *a=adapters;a;a=a->Next) for(IP_ADDR_STRING *ip=&a->IpAddressList;ip;ip=ip->Next) {
   if(strcmp(ip->IpAddress.String,"0.0.0.0") && addresses<128){if(addresses++)add(",");str(ip->IpAddress.String);}
  }
  add("]}");free(adapters);

}
