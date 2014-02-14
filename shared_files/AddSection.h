#ifndef ADDSEC_H
#define ADDSEC_H
#include <windows.h>
#define PEAlign(a, b) (((a + b - 1) / b) * b)

PIMAGE_SECTION_HEADER AddSection(PCHAR szName, DWORD dwSize, PIMAGE_NT_HEADERS pNtHeaders, DWORD dwFlags);
#endif