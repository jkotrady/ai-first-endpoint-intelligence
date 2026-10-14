#include "collector.h"
#include <stdarg.h>
char output[CAP];
size_t used;
int overflow;
volatile LONG stopping;
void add(const char *fmt,...) {
 va_list ap; int n; if(overflow) return;
 va_start(ap,fmt); n=vsnprintf(output+used,CAP-used,fmt,ap); va_end(ap);
 if(n<0 || (size_t)n>=CAP-used) {overflow=1;return;} used+=(size_t)n;
}
void str(const char *s) {
 add("\""); for(;*s;s++) {unsigned char c=(unsigned char)*s;
 if(c=='"'||c=='\\') add("\\%c",c); else if(c<32) add("\\u%04x",c); else add("%c",c);
 } add("\"");
}
void wstr(const WCHAR *s) {
 char b[24576]; if(!WideCharToMultiByte(CP_UTF8,0,s,-1,b,sizeof(b),NULL,NULL)) {overflow=1;return;} str(b);
}
void error_result(const char *code,DWORD winerr) {used=0;overflow=0;add("{\"status\":\"error\",\"error\":");str(code);add(",\"win32_error\":%lu}",(unsigned long)winerr);}
