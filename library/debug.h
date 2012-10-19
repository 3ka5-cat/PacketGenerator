#include <Windows.h>
#include <stdio.h>
#define DBG
#define DBG_MUTEX_NAME "Global\\FuzzMutex"
#define M_ALLOC(_size_) LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, (ULONG)(_size_))
#define M_FREE(_addr_) LocalFree((_addr_))

/*
BOOL DbgInit(char *lpszDbgLogPath);
void LogMsg(char *lpszFile, int iLine, char *lpszMsg, ...);
*/
#ifdef DBG
void DbgMsg(char *lpszFile, int iLine, char *lpszMsg, ...);
void DbgHexdump(PUCHAR Data, DWORD dwLength);
#else
#define DbgMsg
#define DbgHexdump
#endif
