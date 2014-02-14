#pragma once
#include "AddSection.h"

// Originally by Ashkbiz Danehkar(now slightly modified)
PIMAGE_SECTION_HEADER AddSection(PCHAR szName, DWORD dwSize, PIMAGE_NT_HEADERS pNtHeaders, DWORD dwFlags)
{
	DWORD roffset, rsize, voffset, vsize;
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders) + pNtHeaders->FileHeader.NumberOfSections - 1;
	
	if(pSection){
		rsize	= PEAlign(dwSize, pNtHeaders->OptionalHeader.SectionAlignment);
		vsize	= rsize;
		roffset = PEAlign(pSection->PointerToRawData + pSection->SizeOfRawData, pNtHeaders->OptionalHeader.FileAlignment);
		voffset = PEAlign(pSection->VirtualAddress + pSection->Misc.VirtualSize, pNtHeaders->OptionalHeader.SectionAlignment);
		
		// we'll likely end up corrupting this table if we continue
		if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress != 0)
			return NULL;

		pSection++;
		memset(pSection, 0, (size_t)sizeof(IMAGE_SECTION_HEADER));
		pSection->PointerToRawData	= roffset;
		pSection->VirtualAddress	= voffset;
		pSection->SizeOfRawData		= rsize;
		pSection->Misc.VirtualSize	= vsize;
		pSection->Characteristics	= dwFlags;
		
		memcpy(pSection->Name, szName, strlen(szName));
		pNtHeaders->FileHeader.NumberOfSections	+= 1;
		pNtHeaders->OptionalHeader.SizeOfImage	= voffset + vsize;
		return (PIMAGE_SECTION_HEADER)pSection;
	}

	return NULL;
}
