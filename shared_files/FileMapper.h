#ifndef FILEMAPPER_H
#define FILEMAPPER_H
#include <windows.h>

typedef struct _MAPINFO {
  HANDLE  hFile;
  HANDLE  hFileMapping;
  LPBYTE  lpBuffer;
} MAPINFO, *LPMAPINFO;

LPMAPINFO	LoadFile(LPCTSTR lpszFileName, DWORD dwStubSize);
VOID 		UnloadFile(LPMAPINFO lpMapInfo);
#endif