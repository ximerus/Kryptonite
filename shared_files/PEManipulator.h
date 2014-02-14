#ifndef PEMANIP_H
#define PEMANIP_H
#include <windows.h>
#include "FileMapper.h"
#define PEAlign(a, b) (((a + b - 1) / b) * b)
DWORD FileToVa(DWORD dwFileAddr, PIMAGE_NT_HEADERS pNtHeaders); // By Napalm
DWORD VaToFile(DWORD dwVirtAddr, PIMAGE_NT_HEADERS pNtHeaders); // By Napalm
DWORD CalcNewChecksum(LPMAPINFO lpMapInfo);
#endif