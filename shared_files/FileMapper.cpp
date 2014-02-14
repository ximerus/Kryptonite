#pragma once
#include "FileMapper.h"

LPMAPINFO LoadFile(LPCTSTR lpszFileName, DWORD dwStubSize)
{
	LPMAPINFO lpMapInfo;
	HANDLE    hFile, hFileMapping;
	LPBYTE    lpBuffer;
	DWORD     dwSize;

	hFile = CreateFile(lpszFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if(hFile != INVALID_HANDLE_VALUE){
		dwSize = GetFileSize(hFile, 0);
		if(dwSize != INVALID_FILE_SIZE)
		{
			if(dwStubSize) dwSize += dwStubSize + 4;
			
			hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, dwSize, NULL);
			if(hFileMapping != NULL)
			{
				lpBuffer = (LPBYTE)MapViewOfFile(hFileMapping, FILE_MAP_ALL_ACCESS, 0, 0, dwSize);
				if(lpBuffer != NULL)
				{
					lpMapInfo = (LPMAPINFO)HeapAlloc(GetProcessHeap(), 0, sizeof(MAPINFO));
					if(lpMapInfo != NULL){
						__try{
							lpMapInfo->hFile = hFile;
							lpMapInfo->hFileMapping = hFileMapping;
							lpMapInfo->lpBuffer     = lpBuffer;
							return lpMapInfo;
						} __except (EXCEPTION_EXECUTE_HANDLER){
							HeapFree(GetProcessHeap(), 0, (LPVOID)lpMapInfo);
						}
					}
				
					UnmapViewOfFile(lpBuffer);
				}
			
				CloseHandle(hFileMapping);
			}
		}
		
		CloseHandle(hFile);
	}
	
	return NULL;
}

VOID UnloadFile(LPMAPINFO lpMapInfo)
{
	if(lpMapInfo != NULL){
		UnmapViewOfFile(lpMapInfo->lpBuffer);
		CloseHandle(lpMapInfo->hFileMapping);
		CloseHandle(lpMapInfo->hFile);
		HeapFree(GetProcessHeap(), 0, (LPVOID)lpMapInfo);
	}
}