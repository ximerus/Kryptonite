#pragma once
#include "ciphers.h"

void RC4(LPBYTE lpBuf, LPBYTE lpKey, DWORD dwBufLen, DWORD dwKeyLen)
{
	int a, b = 0, s[256];
	BYTE swap;
	DWORD dwCount;
	for(a = 0; a < 256; a++)
		s[a] = a;
	
	for(a = 0; a < 256; a++){
		b = (b + s[a] + lpKey[a % dwKeyLen]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
	}

	for(dwCount = 0; dwCount < dwBufLen; dwCount++){
		a = (a + 1) % 256;
		b = (b + s[a]) % 256;
		swap = s[a];
		s[a] = s[b];
		s[b] = swap;
		lpBuf[dwCount] ^= s[(s[a] + s[b]) % 256];
	}
}