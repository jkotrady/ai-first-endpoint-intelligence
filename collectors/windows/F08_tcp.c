#include "collector.h"

void collect_F08(void) {
  ULONG size=0;DWORD rc=GetExtendedTcpTable(NULL,&size,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);MIB_TCPTABLE_OWNER_PID *table;unsigned count=0;
  if(rc!=ERROR_INSUFFICIENT_BUFFER || size>CAP){error_result("tcp_table_size",rc);return;}
  table=(MIB_TCPTABLE_OWNER_PID*)malloc(size);if(!table){error_result("memory_limit",0);return;}
  rc=GetExtendedTcpTable(table,&size,TRUE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);if(rc!=NO_ERROR){free(table);error_result("tcp_table_failed",rc);return;}
  add("{\"family\":\"IPv4\",\"pid_available\":true,\"items\":[");
  for(count=0;count<table->dwNumEntries && count<512 && used<CAP-1024 && !stopping;count++){
   MIB_TCPROW_OWNER_PID *r=&table->table[count];struct in_addr addr;
   if(count) { add(","); }
   add("{\"local_ip\":");addr.s_addr=r->dwLocalAddr;str(inet_ntoa(addr));add(",\"local_port\":%u,\"remote_ip\":",ntohs((u_short)r->dwLocalPort));addr.s_addr=r->dwRemoteAddr;str(inet_ntoa(addr));add(",\"remote_port\":%u,\"state\":%lu,\"pid\":%lu}",r->dwState==MIB_TCP_STATE_LISTEN?0:ntohs((u_short)r->dwRemotePort),(unsigned long)r->dwState,(unsigned long)r->dwOwningPid);
  }
  add("],\"status\":\"%s\",\"count\":%u}",count<table->dwNumEntries?"partial":"complete",count);free(table);

}
