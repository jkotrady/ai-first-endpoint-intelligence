/* Visible foreground worker. Dispatch is defined by collectors/catalog.json. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/net_sockets.h>

#include "collector.h"
#include "catalog_generated.h"
static char reply[8192];
static char host[128], port[8], name[128], token[65], ca[260];

int mbedtls_hardware_poll(void *ctx,unsigned char *buf,size_t len,size_t *olen) {
 HCRYPTPROV prov=0; (void)ctx; *olen=0;
 if(len>0xffffffffU || !CryptAcquireContextA(&prov,NULL,NULL,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT|CRYPT_SILENT)) return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
 BOOL ok=CryptGenRandom(prov,(DWORD)len,buf); CryptReleaseContext(prov,0);
 if(!ok) { return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED; }
 *olen=len; return 0;
}
static BOOL WINAPI on_signal(DWORD signal) { (void)signal; InterlockedExchange(&stopping,1); return TRUE; }
static int hexid(const char *s) {size_t i;if(strlen(s)!=64)return 0;for(i=0;i<64;i++)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return 0;return 1;}
static int config(const char *path) {
 FILE *f=fopen(path,"rb");char b[1024];if(!f)return 0;
 if(!fgets(b,sizeof(b),f)){fclose(f);return 0;}fclose(f);
 /* fixed values; tokens and paths cannot inject HTTP headers */
 if(sscanf(b,"%127s %7s %127s %64s %259s",host,port,name,token,ca)!=5 || !hexid(token))return 0;
 return 1;
}
static int request(const char *path,const char *body,size_t len) {
 mbedtls_net_context net;mbedtls_ssl_context ssl;mbedtls_ssl_config conf;mbedtls_x509_crt cert;mbedtls_entropy_context entropy;mbedtls_ctr_drbg_context rng;
 char hdr[2048];int rc=-1,n,tls_error=0;const char *stage="entropy";size_t done=0,total=0;const unsigned char personal[]="forensics-pilot-v1";
 mbedtls_net_init(&net);mbedtls_ssl_init(&ssl);mbedtls_ssl_config_init(&conf);mbedtls_x509_crt_init(&cert);mbedtls_entropy_init(&entropy);mbedtls_ctr_drbg_init(&rng);
 if((tls_error=mbedtls_ctr_drbg_seed(&rng,mbedtls_entropy_func,&entropy,personal,sizeof(personal)-1))!=0)goto out;
 stage="ca_file";
 if((tls_error=mbedtls_x509_crt_parse_file(&cert,ca))!=0)goto out;
 stage="configuration";
 if(mbedtls_ssl_config_defaults(&conf,MBEDTLS_SSL_IS_CLIENT,MBEDTLS_SSL_TRANSPORT_STREAM,MBEDTLS_SSL_PRESET_DEFAULT)!=0)goto out;
 mbedtls_ssl_conf_authmode(&conf,MBEDTLS_SSL_VERIFY_REQUIRED);mbedtls_ssl_conf_ca_chain(&conf,&cert,NULL);mbedtls_ssl_conf_rng(&conf,mbedtls_ctr_drbg_random,&rng);
 mbedtls_ssl_conf_min_tls_version(&conf,MBEDTLS_SSL_VERSION_TLS1_2);mbedtls_ssl_conf_max_tls_version(&conf,MBEDTLS_SSL_VERSION_TLS1_2);mbedtls_ssl_conf_read_timeout(&conf,10000);
 if(mbedtls_ssl_setup(&ssl,&conf)!=0 || mbedtls_ssl_set_hostname(&ssl,name)!=0)goto out;
 stage="connect";if((tls_error=mbedtls_net_connect(&net,host,port,MBEDTLS_NET_PROTO_TCP))!=0)goto out;
 {DWORD timeout=10000;setsockopt((SOCKET)net.fd,SOL_SOCKET,SO_RCVTIMEO,(char*)&timeout,sizeof(timeout));setsockopt((SOCKET)net.fd,SOL_SOCKET,SO_SNDTIMEO,(char*)&timeout,sizeof(timeout));}
 mbedtls_ssl_set_bio(&ssl,&net,mbedtls_net_send,mbedtls_net_recv,mbedtls_net_recv_timeout);
 stage="handshake";if((tls_error=mbedtls_ssl_handshake(&ssl))!=0 || mbedtls_ssl_get_verify_result(&ssl)!=0)goto out;
 stage="http_io";
 n=snprintf(hdr,sizeof(hdr),"POST %s HTTP/1.1\r\nHost: %s\r\nAuthorization: Bearer %s\r\nX-Agent-Collectors: " COLLECTOR_IDS "\r\nX-Agent-Source: " AGENT_SOURCE_SHA256 "\r\nContent-Type: application/json\r\nContent-Length: %u\r\nConnection: close\r\n\r\n",path,name,token,(unsigned)len);
 if(n<=0 || n>=(int)sizeof(hdr))goto out;
 while(done<(size_t)n){int w=mbedtls_ssl_write(&ssl,(unsigned char*)hdr+done,(size_t)n-done);if(w<=0)goto out;done+=(size_t)w;}
 done=0;while(done<len){int w=mbedtls_ssl_write(&ssl,(const unsigned char*)body+done,len-done);if(w<=0)goto out;done+=(size_t)w;}
 while(total<sizeof(reply)-1){int r=mbedtls_ssl_read(&ssl,(unsigned char*)reply+total,sizeof(reply)-1-total);if(r==0||r==MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)break;if(r<0)goto out;total+=(size_t)r;}
 if(total==sizeof(reply)-1) { goto out; }
 reply[total]=0;
 if(sscanf(reply,"HTTP/1.1 %d",&rc)!=1)rc=-1;
 out:if(rc<0)fprintf(stderr,"Connection failed: stage=%s tls=%d verify=%lu\n",stage,tls_error,(unsigned long)mbedtls_ssl_get_verify_result(&ssl));mbedtls_net_free(&net);mbedtls_ssl_free(&ssl);mbedtls_ssl_config_free(&conf);mbedtls_x509_crt_free(&cert);mbedtls_ctr_drbg_free(&rng);mbedtls_entropy_free(&entropy);return rc;
}
static int atomic_file(const char *path,const char *data,size_t n) {
 char tmp[300];FILE*f;snprintf(tmp,sizeof(tmp),"%s.tmp",path);f=fopen(tmp,"wb");if(!f)return 0;
 int ok=fwrite(data,1,n,f)==n; if(fflush(f)!=0)ok=0;if(fclose(f)!=0)ok=0;
 if(!ok) { return 0; }
 return MoveFileExA(tmp,path,MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH)!=0;
}
int main(int argc,char **argv) {
 WSADATA wd;SetConsoleCtrlHandler(on_signal,TRUE);SetPriorityClass(GetCurrentProcess(),BELOW_NORMAL_PRIORITY_CLASS);
 if(WSAStartup(MAKEWORD(2,2),&wd))return 1;
 if(argc==2 && !strcmp(argv[1],"--list")){puts(COLLECTOR_CATALOG_JSON);WSACleanup();return 0;}
 if(argc==2 && !strcmp(argv[1],"--version")){puts(AGENT_SOURCE_SHA256);WSACleanup();return 0;}
 if(argc==3 && !strcmp(argv[1],"--collect")){collect(argv[2]);puts(output);WSACleanup();return strstr(output,"\"status\":\"error\"")?2:0;}
 if(argc==3 && !strcmp(argv[1],"--probe") && config(argv[2])) {int status=request("/agent/check","{}",2);printf("Connection check HTTP %d\n",status);WSACleanup();return status==204?0:4;}
 if(argc!=3 || strcmp(argv[1],"--run") || !config(argv[2])){fprintf(stderr,"Usage: forensics-agent --collect ID OR --list OR --version OR --run agent.conf\n");return 2;}
 HANDLE singleton=CreateMutexA(NULL,TRUE,"Local\\ForensicsPilotAgent");
 if(!singleton || GetLastError()==ERROR_ALREADY_EXISTS){fprintf(stderr,"Agent already running or mutex unavailable\n");return 3;}
 printf("Forensics pilot foreground agent. Allowed: %s. Ctrl+C stops.\n",COLLECTOR_IDS);fflush(stdout);
 while(!stopping){
  FILE*f=fopen("pending.json","rb");
  if(f){size_t n=fread(output,1,CAP-1,f);int extra=fgetc(f);fclose(f);output[n]=0;
   if(extra!=EOF){fprintf(stderr,"Pending result exceeds limit; manual review required\n");break;}
   int status=request("/agent/result",output,n);if(status==204){DeleteFileA("pending.json");printf("Result acknowledged\n");}else {printf("Result upload pending (%d)\n",status);Sleep(5000);continue;}
  }
  collect("F01");int status=request("/agent/poll",output,used);
  if(status==200){char *b=strstr(reply,"\r\n\r\n"),job[65],nonce[65],id[4],source[65],extra;
   if(b && sscanf(b+4,"JOB2 %64s %64s %3s %64s %c",job,nonce,id,source,&extra)==4 && hexid(job)&&hexid(nonce) && !strcmp(source,AGENT_SOURCE_SHA256) && collector_allowed(id)){
    char previous[80]={0};f=fopen("last-job.txt","rb");if(f){fgets(previous,sizeof(previous),f);fclose(f);}
    if(!strcmp(previous,job)){Sleep(1000);continue;}
    if(!atomic_file("last-job.txt",job,64)){fprintf(stderr,"Cannot persist execution marker\n");break;}
    collect(id);char *data=(char*)malloc(used+1);if(!data)break;memcpy(data,output,used+1);used=0;overflow=0;
    add("{\"job_id\":\"%s\",\"nonce\":\"%s\",\"collector_id\":\"%s\",\"data\":%s}",job,nonce,id,data);free(data);
    if(overflow || !atomic_file("pending.json",output,used)){fprintf(stderr,"Cannot persist result\n");break;}
    printf("Collected %s; result queued\n",id);fflush(stdout);continue;
   }
  }else if(status!=204)printf("Poll failed (%d); no job executed\n",status);
  fflush(stdout);for(int i=0;i<50&&!stopping;i++)Sleep(100);
 }
 WSACleanup();return 0;
}
