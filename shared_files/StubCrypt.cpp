#pragma once
#include "StubCrypt.h"

DWORD CryptStubFile(LPMAPINFO lpStubInfo, int nMorph)
{
	LPBYTE  pStartSig, pEndSig, lpStart, lpEnd, lpTemp;
	DWORD dwCryptedBlockSize = 0, dwStubSize;
	char cKeyChar = 'A', szKey[13];
	int i, nOffset;
	
	srand(GetTickCount());
	
	// generate 12 byte RC4 key
	for(i = 0; i < 12; i++){
		nOffset = rand() % 26;
		szKey[i] = (cKeyChar + nOffset);
	}
	
	szKey[12] = 0;
	
	// locate stub crypt start/end signatures
	dwStubSize	= GetFileSize(lpStubInfo->hFile, NULL);
	if(dwStubSize != INVALID_FILE_SIZE){
		lpStart = (lpStubInfo->lpBuffer);
		lpEnd   = (lpStart + dwStubSize);
		
		while(lpStart < lpEnd){
			if(nMorph){
				// update crypto key in stub
				if(!memcmp(lpStart, "HavocBounded", 12)){	
					printf("[+] Morphing stub\n\t[+] Found crypto key; Updating to '%s'\n[+] Stub morphed\n", szKey);
					for(i = 0; i < 12; i++){
						*(BYTE *)(lpStart + i) = szKey[i];
					}
				}
			}
			
			// locate start marker
			if(!memcmp(lpStart, "\xDE\xAD\xC0\xDE", 4)){ 		     // start sig: 0xDEADC0DE
				// store start tag offset
				pStartSig = lpStart;
				lpTemp = lpStart += 4; // skip start sig
				
				// locate end tag
				while(lpTemp < lpEnd){
					if(!memcmp(lpTemp, "\xDE\xAD\xBE\xEF", 4)){		// end sig: 0xDEADBEEF
						pEndSig = lpTemp;
						
						// store nStubSize
						dwCryptedBlockSize = ((DWORD)pEndSig - (DWORD)pStartSig);
						
						// erase start and end signature
						memset(pStartSig, 0x90, 4);
						memset(pEndSig, 0x90, 4);
					
						RC4(pStartSig, (nMorph == 1) ? (unsigned char *)szKey : (unsigned char *)"HavocBounded", dwCryptedBlockSize, 12);		
					}
					
					lpTemp++;
				}
			}
			lpStart++;
		}
	}
	
	FlushViewOfFile(lpStubInfo->lpBuffer, 0);
	return dwCryptedBlockSize;
}