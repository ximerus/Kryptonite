#ifndef CRYPTMEM_H
#define CRYPTMEM_H

//#pragma comment(lib, "dbghelp.lib")
//#pragma comment(lib, "imagehlp.lib")
#include <windows.h>
#include <imagehlp.h>
#include <stdio.h>

#include "..\shared_files\FileMapper.h"
#include "..\shared_files\AddSection.h"
#include "..\shared_files\PEManipulator.h"
#include "..\shared_files\stubCrypt.h"

#include "..\shared_files\FileMapper.cpp"
#include "..\shared_files\AddSection.cpp"
#include "..\shared_files\PEManipulator.cpp"
#include "..\shared_files\x86opsize.cpp"
#include "..\shared_files\vopcodes.h"
#include "..\shared_files\stubCrypt.cpp"
#define USE_VM 0x80000003

int CryptMem(char *szTargetFile, char *szStubFile, DWORD dwFlags);
#endif