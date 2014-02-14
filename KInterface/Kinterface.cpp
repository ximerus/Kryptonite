// Simple wrapper for KMC/KBC (C) KOrUPt
//	V1.0
#pragma comment(linker,"/BASE:0x400000 /FILEALIGN:0x200 /MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR /IGNORE:4078")
#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "imagehlp.lib")

#include <windows.h>
#include <stdio.h>
#include <imagehlp.h>

#include "..\KBinCrypt\CryptFile.h"
#include "..\KBinCrypt\CryptFile.cpp"
#include "..\KMemCrypt\CryptMem.h"
#include "..\KMemCrypt\CryptMem.cpp"

int main(int argc, char **argv)
{
	DWORD dwFlags = 0;
	char szChoice[3];
	
	printf("\t\t---------KCrypt Engine v2.0 By KOrUPt---------\n\n");
	if(argc != 3){
		printf(
			"Usage: %s <target file> <encryption key>\n\n", argv[0]);
		return 0;
	}
	
	printf("[?] Does %s use PCODE markers? y/n ", argv[1]);
	fgets(szChoice, 2, stdin);
	if(szChoice[0] == 'y'){
		printf("[*] Encrypting marked code segments\n");
		if(CryptMem(argv[1], "..\\stub_files\\kmemcrypt\\kmc_stub", 0) != 1){
			printf("[-] An unknown error occurred whilst trying to memcrypt '%s'\n", argv[1]);
			return 0;
		}
	}
	
	fflush(stdin);
	printf("[?] Would you like %s to be crypted? y/n ", argv[1]);
	fgets(szChoice, 2, stdin);
	if(szChoice[0] == 'y'){
		fflush(stdin);
		printf("[?] Morph stub? y/n ");
		fgets(szChoice, 2, stdin);
		if(szChoice[0] == 'y')
			dwFlags |= MORPH_STUB;
		
		fflush(stdin);
		printf("[?] Add random Import Address Table? y/n ");
		fgets(szChoice, 2, stdin);
		if(szChoice[0] == 'y')
			dwFlags |= ADD_RANDOM_IAT;
	
		if(CryptFile(argv[1], "..\\stub_files\\kbincrypt\\kbc_stub", argv[2], dwFlags) != 1){
			printf("[-] An unknown error occurred whilst trying to filecrypt '%s'\n", argv[1]);
			return 0;
		}else printf("[+] %s crypted successfully\n\n", argv[1]);
	}
	
	return 1;
}
