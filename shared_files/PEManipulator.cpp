#pragma once
#include "PEManipulator.h"

DWORD FileToVa(DWORD dwFileAddr, PIMAGE_NT_HEADERS pNtHeaders) // By Napalm
{
    PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
    for(WORD wSections = 0; wSections < pNtHeaders->FileHeader.NumberOfSections; wSections++){
        if(dwFileAddr >= lpSecHdr->PointerToRawData){
            if(dwFileAddr < (lpSecHdr->PointerToRawData + lpSecHdr->SizeOfRawData)){
                dwFileAddr -= lpSecHdr->PointerToRawData;
                dwFileAddr += (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress);
                return dwFileAddr; 
            }
        }
		
		lpSecHdr++;
    }
    
    return NULL;
}

DWORD VaToFile(DWORD dwVirtAddr, PIMAGE_NT_HEADERS pNtHeaders)
{
	PIMAGE_SECTION_HEADER lpSecHdr = (PIMAGE_SECTION_HEADER)((DWORD)pNtHeaders + sizeof(IMAGE_NT_HEADERS));
	DWORD dwReturn = dwVirtAddr;
	for(WORD wSections = 0; wSections < pNtHeaders->FileHeader.NumberOfSections; wSections++){
		if(dwReturn >= (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress)){
			if(dwReturn < (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress + lpSecHdr->Misc.VirtualSize)){
				dwReturn -= (pNtHeaders->OptionalHeader.ImageBase + lpSecHdr->VirtualAddress);
				dwReturn += lpSecHdr->PointerToRawData;
				return dwReturn; 
			}
		}
		lpSecHdr++;
	}
	return NULL;
}

DWORD CalcNewChecksum(LPMAPINFO lpMapInfo)
{
    DWORD dwHeaderSum, dwCheckSum, dwSize;
	PIMAGE_NT_HEADERS pNtHeaders;
	
	if((dwSize = GetFileSize(lpMapInfo->hFile, NULL)) != INVALID_FILE_SIZE){
		pNtHeaders = CheckSumMappedFile(lpMapInfo->lpBuffer, dwSize, &dwHeaderSum, &dwCheckSum);
		if(pNtHeaders)
			if(dwHeaderSum)
				return pNtHeaders->OptionalHeader.CheckSum;
	}
	
	return NULL;
}