#ifndef STUBCRYPT_H
#define STUBCRYPT_H
#include <windows.h>
#include <stdio.h>
#include "FileMapper.h"
#include "ciphers.h"
DWORD CryptStubFile(LPMAPINFO lpStubInfo, int nMorph);
#endif