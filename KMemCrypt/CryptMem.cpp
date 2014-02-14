
/*========================================================
		KMemCrypt BETA v1.0 (C) KOrUPt
		
	This file contains the PE memory crypt engine of Kryptonite,
	it takes care of encrypting and decrypting chunks of
	memory on the fly, thus making target regions never
	fully visible in memory.

========================================================*/
#pragma once
#include "CryptMem.h"

int CryptMem(char *szTargetFile, char *szStubFile, DWORD dwFlags)
{
	LPMAPINFO lpTargetFile, lpStubFile;
	PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER lpSecHdr, lpSection;
	LPBYTE  pStartSig, pEndSig,  pSehSig;
	DWORD  	dwStubSize, dwWriteOffset;
	char 	*pszErrorMsg;
	int		nStatus = 0;

	int i = 0, nSigCount = 0, nTotalBytes = 0, nInstructionLen;
	int nInstructionsVirtualized =  0;
	bool bTagFound = false;
	const int xorkey = 0xC3;
	
	// set error string in advance
	pszErrorMsg = "- Could not load target/stub file";
	
	// load stub file
	lpStubFile = LoadFile(szStubFile, NULL);
	if(lpStubFile)
	{
		dwStubSize	= GetFileSize(lpStubFile->hFile, NULL);
		if(dwStubSize != INVALID_FILE_SIZE)
		{
			// load target file
			lpTargetFile = LoadFile(szTargetFile, NULL);
			if(lpTargetFile)
			{
				// check PE headers and make sure executable is 32bit
				if((pNtHeaders = ImageNtHeader(lpTargetFile->lpBuffer))){
					if(pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386){
						// we can work with this, so reload file + stub size bytes
						i = PEAlign(dwStubSize, pNtHeaders->OptionalHeader.SectionAlignment);
						UnloadFile(lpTargetFile);
						lpTargetFile = LoadFile(szTargetFile, i);
					
						// check for executable sections
						lpSecHdr = IMAGE_FIRST_SECTION(pNtHeaders);
						for(int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++){
							// is section executable?
							if(lpSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
							{
								// set pointers to start and end of section
								LPBYTE lpStart = (lpTargetFile->lpBuffer + lpSecHdr->PointerToRawData);
								LPBYTE lpEnd   = (lpStart + lpSecHdr->SizeOfRawData);
								
								// make section readable, writable and executable
								lpSecHdr->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_WRITE;
								// ^ KBinCrypt's stub takes care of this!
								
								// search section byte by byte and locate start/end markers
								while(lpStart < lpEnd){
									// while we're here check for SEH address placeholder
									if(!memcmp(lpStart, "\xCA\xFE\xBA\xBE", 4)){
										printf("\n[+] KMC: Found SEH signature @ section %s\n\n", lpSecHdr->Name);
										// remove SEH address placeholder
										memset(lpStart, 0x90, 4);
										lpStart += 5; // 4 byte sig, 1 byte mov instruction
										pSehSig = lpStart;
									}
									
									// locate start marker
									if(!memcmp(lpStart, "\xDE\xAD\xC0\xDE", 4)){ 		     // start sig: 0xDEADC0DE
										// store start tag offset
										lpStart += 4; // skip start tag
										pStartSig = lpStart;
										
										// locate end tag
										while(lpStart < lpEnd){
											if(!memcmp(lpStart, "\xDE\xAD\xBE\xEF", 4)){	// end sig: 0xDEADBEEF
												// make a note that end tag was found
												bTagFound = true;
												break;
											}
											
											lpStart++;
										}
										
										// if we have an end tag, encrypt code inbetween tags
										if(bTagFound){
											pEndSig = lpStart; // store end tag offset
											
											// update status
											printf("[*] KMC: Encrypting %d bytes(pcode block %d)\n", 
												((DWORD)pEndSig - (DWORD)pStartSig),
												nSigCount + 1);
											
											// update statisitcal data
											nTotalBytes += ((DWORD)pEndSig - (DWORD)pStartSig);
											
											// erase start and end signature
											memset((pStartSig - 4), 0x90 ^ xorkey, 4);
											memset((pEndSig), 0x90, 4);
											
											// xor code inbetween tags
											while(pStartSig < pEndSig){
												nInstructionLen = x86opsize(pStartSig);
												/*
												// virtualize opcodes within tags
												(FUNCTIONALITY UNSTABLE)
												if((dwFlags & USE_VM) == USE_VM){
													if(nInstructionLen == 1){
														// check for neg 32
														// check for mov r32, r32
														// check for inc r32 [x]
														// check for dec r32
														if(*(BYTE *)pStartSig >= 0x40 && *(BYTE *)pStartSig <= 0x47){ 
															switch(*(BYTE *)pStartSig & 0xF){
																case 0x0: // inc eax
																	*pStartSig = V_INC_EAX;
																	nInstructionsVirtualized++;
																	break;
																case 0x1: // inc ebx
																	*pStartSig = V_INC_EBX;
																	nInstructionsVirtualized++;
																	break;
																case 0x2: // inc ecx
																	*pStartSig = V_INC_ECX;
																	nInstructionsVirtualized++;
																	break;
																case 0x3: // inc esi
																	*pStartSig = V_INC_ESI;
																	nInstructionsVirtualized++;
																	break;
																case 0x4: // inc edi
																	*pStartSig = V_INC_EDI;
																	nInstructionsVirtualized++;
																	break;
																case 0x5: // inc edx
																	*pStartSig = V_INC_EDX;
																	nInstructionsVirtualized++;
																	break;
																case 0x6: // inc esp
																	*pStartSig = V_INC_ESP;
																	nInstructionsVirtualized++;
																	break;
																case 0x7: // inc ebp
																	*pStartSig = V_INC_EBP;
																	nInstructionsVirtualized++;
																	break;
															}
														}
													}
												}
												*/
												
												// encrypt code
												for(i = 0; i < nInstructionLen; i++)
													*(pStartSig + i) ^= xorkey;
												pStartSig += nInstructionLen;
											}
											
											// incremenent encrypted block count and reset end tag identifier
											nSigCount++;
											bTagFound = false;
										}else{
											// couldn't find a matching end tag
											printf("[-] KMC: Could not find matching end tag @ pcode block %d\n", nSigCount + 1);
											break;
										}
									}else lpStart++; // keep on looking for start marker
								}
							}
							lpSecHdr++;	// next section to search
						}
						
						// append new section and write SE handler(stub) into target file
						if(nSigCount > 0){
							i = PEAlign(dwStubSize, pNtHeaders->OptionalHeader.SectionAlignment);
							lpSection = AddSection(".pcode", i, pNtHeaders, IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE); 
							if(lpSection){
								printf("[+] KMC: Added new section .pcode @ 0x%x\n", lpSection->PointerToRawData);
								
								// update SEH handler address
								*(DWORD *)(pSehSig) 
									= FileToVa(lpSection->PointerToRawData, pNtHeaders);
								
								// fill section with nops
								memset(lpTargetFile->lpBuffer + lpSection->PointerToRawData, 0x90, lpSection->SizeOfRawData);
								
								// write stub code into section
								dwWriteOffset = lpSection->PointerToRawData;
								memcpy(lpTargetFile->lpBuffer + dwWriteOffset, lpStubFile->lpBuffer, dwStubSize);
								
								// calc new checksum
								CalcNewChecksum(lpTargetFile);
								
								// our job is done 
								pszErrorMsg = "+ KMC: Stub written\n";
								nStatus = 1;
							}
						}							
						
					}
				}
				
				FlushViewOfFile(lpTargetFile->lpBuffer, 0);
				UnloadFile(lpTargetFile);
			}
		}
		UnloadFile(lpStubFile);
	}
	
	printf("[*] KMC: Encrypted %d code blocks(%d bytes); Virtualized %d instructions\n", nSigCount, nTotalBytes, nInstructionsVirtualized);
	printf("[%c]%s%s\n", pszErrorMsg[0], pszErrorMsg[0] == '-' ? " Error!" : " Success!", pszErrorMsg + 1);
	return nStatus;
}