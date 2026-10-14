#ifndef FORENSICS_COLLECTOR_H
#define FORENSICS_COLLECTOR_H
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CAP 262144
extern char output[CAP];
extern size_t used;
extern int overflow;
extern volatile LONG stopping;
void add(const char *fmt,...);
void str(const char *s);
void wstr(const WCHAR *s);
void error_result(const char *code,DWORD winerr);
int collector_allowed(const char *id);
void collect(const char *id);
#endif
