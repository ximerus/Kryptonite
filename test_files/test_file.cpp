#pragma comment(linker,"/OPT:nowin98 /BASE:0x400000 /FILEALIGN:0x200 /MERGE:.data=.text /SECTION:.text,EWR /IGNORE:4078")
#define WIN_32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x501
#include <winsock2.h>
#include <windows.h>
#include <stdio.h>
#include "..\shared_files\KMemCryptP.h"

void N4()
{
	unsigned long dwReturnAddress;
	printf("In N4()\n");
	
	P_CODE_START
		for(int i = 0; i < 5; i++)
			printf("%d ", i);
	printf("\n");
	P_CODE_END
	printf("Starting return cycle\n");
	return;
}

void N3()
{
	unsigned long dwReturnAddress;
	printf("In N3()\n");
	
	P_CODE_START
		for(int i = 0; i < 5; i++)
			printf("%d ", i);
	printf("\nCalling N4()\n");
	N4();
	P_CODE_END
	return;
}

void N2()
{
	unsigned long dwReturnAddress;
	printf("In N2()\n");
	
	P_CODE_START
		for(int i = 0; i < 5; i++)
			printf("%d ", i);
	printf("\nCalling N3()\n");
	N3();
	P_CODE_END
	return;
}

void N1()
{
	unsigned long dwReturnAddress;
	printf("In N1()\n");
	
	P_CODE_START
		for(int i = 0; i < 5; i++)
			printf("%d ", i);
	printf("\nCalling N2()\n");
	N2();
	P_CODE_END
	return;
}


int main(void)
{
	P_CODE_INSTALL_SEH
	char username[20]; // key for KOrUPt is 4559164
	unsigned int eax, edx;
	unsigned long dwReturnAddress;
	printf("In main()\n");
	
	// test nesting functiona calls
	P_CODE_START
		printf("1st call\n");
		N1();
	P_CODE_END
	
	printf("Repeating\n");
	P_CODE_START
		printf("1st call\n");
		N1();
	P_CODE_END
	
	printf("\nNested call test complete\n");
	
	P_CODE_UNINSTALL_SEH
	return 0;
}