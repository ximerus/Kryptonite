#ifndef CRYPTFILE_H
#define CRYPTFILE_H

#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>

#include "itmaker.h"
#include "itmaker.cpp"

#include "..\shared_files\FileMapper.h"
#include "..\shared_files\AddSection.h"
#include "..\shared_files\PEManipulator.h"
#include "..\shared_files\Ciphers.h"

#include "..\shared_files\FileMapper.cpp"
#include "..\shared_files\AddSection.cpp"
#include "..\shared_files\PEManipulator.cpp"
#include "..\shared_files\Ciphers.cpp"

#define MORPH_STUB 0x80000001
#define ADD_RANDOM_IAT 0x80000002

BOOL CryptFile(const char *target, const char *stub, const char *szKey, const DWORD dwFlags);
#endif