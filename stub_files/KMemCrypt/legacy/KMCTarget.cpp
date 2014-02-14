/*=========================================
	KMemCrypt C Stub BETA V2.0 (C) KOrUPt
	
	Known issues:
	Changelog:
	Instructions:
		1. Execute KMCTest.bat
*/
#pragma comment(linker,"/BASE:0x400000 /FILEALIGN:0x200 /MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR /IGNORE:4078")
#define WIN_32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x501
#define _DEBUG 1
#include <windows.h>
#include <stdio.h>

#define MAX_NESTED_CALLS 5
#define MAX_INSTRUCTION_LENGTH 16

#include "..\..\shared_files\x86opsize.cpp"
#include "..\..\shared_files\vopcodes.h"
#include "..\..\shared_files\x86opcodes.h"
#include "..\..\shared_files\KMemCryptP.h"

// below macro's are unused in external
#define INSTALL_SEH(i) \
	__asm{lea eax, i}   \
	__asm{push eax} \
	__asm{push fs:0} \
	__asm{mov fs:0, esp } \

#define UNINSTALL_SEH  \
	__asm{pop FS:0} \
	__asm{add esp, 4} \
	__asm{pop FS:0} \
	__asm{add esp, 4} \


// globals - required by exception handler
DWORD 	dwOpcodeBackup[MAX_NESTED_CALLS];				
DWORD	*dwPrevInstructionAddr;
int		nPrevInstructionLen;
int 	nNestingLevel	= 0;
BOOL  	bIsVirtualInstruction = FALSE;			
BYTE 	bInstructionCache[MAX_INSTRUCTION_LENGTH];

int EnterVM(unsigned char *bInstructionCache, BOOL *bIsVirtualInstruction, _CONTEXT *ContextRecord);

// basically our stub in its C form
ULONG seh(_EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, _CONTEXT *ContextRecord, void * DispatcherContext)
{
	const int nImageBase	= 0x00400000; // hardcoded - to be updated by loader
	const BYTE bXorkey 		= 0xC3;		  // xor key constant
	DWORD dwDynImageBase	= ((DWORD)ExceptionRecord->ExceptionAddress & 0xFFFF0000);
	DWORD dwSavedEip;
	BYTE *lpByte;
	int  i;
	
	printf("eip: 0x%08X: ", (ContextRecord->Eip));
	for(int x = 0; x < 4; x++)
		printf("%02X ", (*(BYTE *)(ContextRecord->Eip + x) ^ bXorkey));
	printf("\n");

	// if we hit our pcode end marker, we must clean up and exit
	if((*(BYTE *)(ContextRecord->Eip) ^ bXorkey) == OPCODE_IN){
		#ifdef _DEBUG		
		printf("Virtualizer : pcode end : decryption stopped\n");
		#endif
		ContextRecord->Eip 		+= 1;	 		
		nPrevInstructionLen		= 0;		
		return EXCEPTION_CONTINUE_SEARCH;
	}
	
	// turn the trap flag back on
	ContextRecord->EFlags |= 0x100;
	
	// if we hit an earlier injected breakpoint, we must remove it and restore the orignal opcode
	if(ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT && dwDynImageBase == nImageBase){
		// decrement nesting level
		if(nNestingLevel > 0) nNestingLevel--;
		
		#ifdef _DEBUG		
		printf("Call handler : Breakpoint removed @ %d\n", nNestingLevel);
		#endif
		
		*(DWORD *)(ExceptionRecord->ExceptionAddress) = dwOpcodeBackup[nNestingLevel];
		// after we've fixed up the bytes, we can decrypt as normal
		goto _DecryptInstruction;
	}
	
	// the trap flag is on, so we continue to decrypt routines
	if(ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP){
		// are we calling a function outside of this module? Perhaps an API?
		// or making a virtual near call?
		// if so, set breakpoint at return address and allow API to execute
		if(dwDynImageBase != nImageBase){
			_VCallGuard:
			DWORD dwRetAddress			  = *(DWORD *)(ContextRecord->Esp); // get caller return address
			dwOpcodeBackup[nNestingLevel] = *(DWORD *)(dwRetAddress);		// save opcode at the return address
			*(BYTE *)(dwRetAddress) 	  = OPCODE_BREAKPOINT; 				// set breakpoint at return address
			
			#ifdef _DEBUG			
			printf("Call handler : Breakpoint set @ %d\n", nNestingLevel);
			#endif
			
			// increment nesting level, as this call may contain pcode markers that make more calls
			// which would result in the orignal opcode being lost
			if(nNestingLevel < MAX_NESTED_CALLS) nNestingLevel++;
			// turn trap flag off as we don't want to step through an external routine
			ContextRecord->EFlags &= !0x100;
			return EXCEPTION_CONTINUE_SEARCH;
		}
		
		_DecryptInstruction:		
		lpByte = (BYTE *)ContextRecord->Eip;
		// cache & decrypt current instructions
		for(i = 0; i < 16; i++) bInstructionCache[i] = *(lpByte + i) ^ bXorkey;
		// encrypt previous instructions
		if(nPrevInstructionLen > 0){
			lpByte = (BYTE *)dwPrevInstructionAddr, i = nPrevInstructionLen;
			while(i--) *(lpByte + i) ^= bXorkey;
		}
		
		// check for unencrypted epilog:
			// mov esp, ebp; pop ebp; ret
		// we don't want to decrypt non-encrypted epilogs so return early.
		// This situation is encountered if we return from a function whilist
		// within pcode macro's(see #kmbc3), where the compiler inserts a jmp
		// to the function epilog outside of the pcode macro's
		if(*(DWORD *)(ContextRecord->Eip) == X86_FUNC_EPILOG){
			#ifdef _DEBUG
			printf("Call handler : Adrupt function exit due to epilog jump\n");
			#endif

			ContextRecord->EFlags	&= !0x100;
			bIsVirtualInstruction	= FALSE;
			nPrevInstructionLen		= 0;
			return EXCEPTION_CONTINUE_SEARCH;	// do not attempt to decrypt!
		}
		
		// store eip so we know if a vncall or vjmp modifies it
		dwSavedEip = ContextRecord->Eip;
		// store address of this [will be previous] instruction
		dwPrevInstructionAddr = (DWORD *)ContextRecord->Eip;
		// x86 code emulator, emulates x86 instructions, returns instruction length
		nPrevInstructionLen = i = EnterVM(bInstructionCache, &bIsVirtualInstruction, ContextRecord);
		// was the instruction emulated?
		if(bIsVirtualInstruction == TRUE){
			bIsVirtualInstruction = FALSE;
			// we don't decrypt instructions here so there is nothing to re-encrypt
			nPrevInstructionLen	  = 0;
			#ifdef _DEBUG
			printf("Current EIP: 0x%08X\nInstruction length: %d\nNew EIP: 0x%08X (%02X)\n", ContextRecord->Eip, i, ContextRecord->Eip + i, *(BYTE *)(ContextRecord->Eip + i) ^ bXorkey);
			#endif
			// place breakpoint after virtual instruction and restore byte's once hit
			dwOpcodeBackup[nNestingLevel] = *(DWORD *)(ContextRecord->Eip + i); 
			*(BYTE *)(ContextRecord->Eip + i) = OPCODE_BREAKPOINT;
			if(nNestingLevel < MAX_NESTED_CALLS) nNestingLevel++;
			// increment eip so instruction is skipped
			ContextRecord->Eip += i;
			// continue execution without decrypting
			return EXCEPTION_CONTINUE_SEARCH;	
		}
		
		// if instruction isn't virutal, decrypt it, let it execute, then re-encrypt it on next cycle
		while(i--) *(BYTE *)(ContextRecord->Eip + i) ^= bXorkey;
	}
	
	// resume execution
	return EXCEPTION_CONTINUE_SEARCH;
}

// handle's virtual instructions and serves as a wrapper for the LDE
int EnterVM(BYTE *bInstructionCache, BOOL *bIsVirtualInstruction, _CONTEXT *ContextRecord)
{
	// presume min instruction length = 1
	int nInstructionLen = 1, n = 0;
	*bIsVirtualInstruction = FALSE;
	
	// vmov [reg32], [reg32]
	// vmov 0xC0-C7 - Eax
	// vmov 0xC8-CF - Ecx
	// vmov 0xD0-D7 - Edx
	// vmov 0xD8-DF	- Ebx
	// vmov 0xE0-E7 - Esp
	// vmov 0xF0-F7 - Esi
	// vmov 0xF8-FF - Edi
	if(bInstructionCache[0] == V_MOV32){ // vmov r32, r32
		#ifdef _DEBUG		
		printf("x86 emu : vmov\n");
		#endif
		
		if(bInstructionCache[1] >= V_MOV_EAX_EAX && bInstructionCache[1] <= V_MOV_EAX_EDI){ 		 // mov eax, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Eax = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Eax = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Eax = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Eax = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Eax = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Eax = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Eax = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Eax = ContextRecord->Edi;
			
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_ECX_EAX && bInstructionCache[1] <= V_MOV_ECX_EDI){ // mov ecx, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Ecx = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ecx = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Ecx = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ecx = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Ecx = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ecx = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Ecx = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Ecx = ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_EDX_EAX && bInstructionCache[1] <= V_MOV_EDX_EDI){ // mov edx, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Edx = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Edx = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Edx = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Edx = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Edx = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Edx = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Edx = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Edx = ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_EBX_EAX && bInstructionCache[1] <= V_MOV_EBX_EDI){ // mov ebx, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Ebx = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ebx = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Ebx = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ebx = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Ebx = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ebx = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Ebx = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Ebx = ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_ESP_EAX && bInstructionCache[1] <= V_MOV_ESP_EDI){ // mov esp, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Esp = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Esp = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Esp = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Esp = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Esp = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Esp = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Esp = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Esp = ContextRecord->Edi;
			
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_EBP_EAX && bInstructionCache[1] <= V_MOV_EBP_EDI){ // mov ebp, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Ebp = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ebp = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Ebp = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ebp = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Ebp = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ebp = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Ebp = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Ebp = ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_ESI_EAX && bInstructionCache[1] <= V_MOV_ESI_EDI){ // mov esi, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Esi = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Esi = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Esi = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Esi = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Esi = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Esi = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Esi = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Esi = ContextRecord->Edi;
			
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_MOV_EDI_EAX && bInstructionCache[1] <= V_MOV_EDI_EDI){ // mov edi, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Edi = ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Edi = ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Edi = ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Edi = ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Edi = ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Edi = ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Edi = ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Edi = ContextRecord->Edi;
			
			*bIsVirtualInstruction = TRUE;
			return 2;
		}
	}
	
	// vadd [reg32], [reg32]
	// vadd 0xC0-C7 - Eax
	// vadd 0xC8-CF - Ecx
	// vadd 0xD0-D7 - Edx
	// vadd 0xD8-DF	- Ebx
	// vadd 0xE0-E7 - Esp
	// vadd 0xF0-F7 - Esi
	// vadd 0xF8-FF - Edi
	if(bInstructionCache[0] == V_ADD32){
		#ifdef _DEBUG		
		printf("x86 emu : vadd\n");
		#endif
		
		if(bInstructionCache[1] >= V_ADD_EAX_EAX && bInstructionCache[1] <= V_ADD_EAX_EDI){ 		 // add eax, r32
			
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Eax += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Eax += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Eax += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Eax += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Eax += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Eax += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Eax += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Eax += ContextRecord->Edi;
			
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_ADD_ECX_EAX && bInstructionCache[1] <= V_ADD_ECX_EDI){ // add ecx, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Ecx += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ecx += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Ecx += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ecx += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Ecx += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ecx += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Ecx += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Ecx += ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_ADD_EDX_EAX && bInstructionCache[1] <= V_ADD_EDX_EDI){ // add edx, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Edx += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Edx += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Edx += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Edx += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Edx += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Edx += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Edx += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Edx += ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_ADD_EBX_EAX && bInstructionCache[1] <= V_ADD_EBX_EDI){ // add ebx, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Ebx += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ebx += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA)	ContextRecord->Ebx += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ebx += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Ebx += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ebx += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Ebx += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Ebx += ContextRecord->Edi;
				
			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_ADD_ESP_EAX && bInstructionCache[1] <= V_ADD_ESP_EDI){ // add esp, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Esp += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Esp += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Esp += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Esp += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Esp += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Esp += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Esp += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Esp += ContextRecord->Edi;

			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_ADD_EBP_EAX && bInstructionCache[1] <= V_ADD_EBP_EDI){ // add ebp, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Ebp += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ebp += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA)	ContextRecord->Ebp += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ebp += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Ebp += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ebp += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Ebp += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Ebp += ContextRecord->Edi;

			*bIsVirtualInstruction = TRUE;
			return 2;
		}else if(bInstructionCache[1] >= V_ADD_ESI_EAX && bInstructionCache[1] <= V_ADD_ESI_EDI){ // add esi, r32
				 if((bInstructionCache[1] & 0xF) == 0x0)	ContextRecord->Esi += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x1)	ContextRecord->Esi += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0x2) 	ContextRecord->Esi += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0x3)	ContextRecord->Esi += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0x4)	ContextRecord->Esi += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0x5)	ContextRecord->Esi += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0x6)	ContextRecord->Esi += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0x7)	ContextRecord->Esi += ContextRecord->Edi;
		
			*bIsVirtualInstruction = TRUE;
			return 2;

		}else if(bInstructionCache[1] >= V_ADD_EDI_EAX && bInstructionCache[1] <= V_ADD_EDI_EDI){ // add edi, r32
				 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Edi += ContextRecord->Eax;
			else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Edi += ContextRecord->Ecx;
			else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Edi += ContextRecord->Edx;
			else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Edi += ContextRecord->Ebx;
			else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Edi += ContextRecord->Esp;
			else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Edi += ContextRecord->Ebp;
			else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Edi += ContextRecord->Esi;
			else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Edi += ContextRecord->Edi;
			
			*bIsVirtualInstruction = TRUE;
			return 2;
		}
	}
	
	if(bInstructionCache[0] == V_NEAR_CALL){
		#ifdef _DEBUG		
		printf("x86 emu : vncall\n");
		#endif
	
		DWORD dwAddress = ContextRecord->Eip += 5; // compute return address
		ContextRecord->Esp -= 4;				   // adjust stack
		*(DWORD *)ContextRecord->Esp = dwAddress;  // push return address
		dwAddress += *(DWORD *)(bInstructionCache + 1); // calc address
		ContextRecord->Eip = dwAddress;			   // set eip to address
		*bIsVirtualInstruction = TRUE;	
		return 5;
	}
	
	// vneg [r32]
	if(bInstructionCache[0] == V_NEG32){
		#ifdef _DEBUG		
		printf("x86 emu : vneg\n");
		#endif		
			 if((bInstructionCache[1] & 0xF) == 0x8)	ContextRecord->Eax--;
		else if((bInstructionCache[1] & 0xF) == 0x9)	ContextRecord->Ecx--;
		else if((bInstructionCache[1] & 0xF) == 0xA) 	ContextRecord->Edx--;
		else if((bInstructionCache[1] & 0xF) == 0xB)	ContextRecord->Ebx--;
		else if((bInstructionCache[1] & 0xF) == 0xC)	ContextRecord->Esp--;
		else if((bInstructionCache[1] & 0xF) == 0xD)	ContextRecord->Ebp--;
		else if((bInstructionCache[1] & 0xF) == 0xE)	ContextRecord->Esi--;
		else if((bInstructionCache[1] & 0xF) == 0xF)	ContextRecord->Edi--;
		
		*bIsVirtualInstruction = TRUE;
		return 2;
	}
		
	// vinc/vdec [reg32]
	if(bInstructionCache[0] >= V_INC_EAX && bInstructionCache[0] <= V_INC_EBP){	
		#ifdef _DEBUG		
		printf("x86 emu : vinc\n");
		#endif
		
		n = 1;	// vinc
	}else if(bInstructionCache[0] >= V_DEC_EAX && bInstructionCache[0] <= V_DEC_EBP){
		#ifdef _DEBUG		
		printf("x86 emu : vdec\n");
		#endif
		
		n = -1; // vdec
	}
	
	// handle addition/subtraction instructions
	if(n != 0){
			 if((bInstructionCache[0] & 0xF) == 0x0) ContextRecord->Eax += n;
		else if((bInstructionCache[0] & 0xF) == 0x1) ContextRecord->Ecx += n;
		else if((bInstructionCache[0] & 0xF) == 0x2) ContextRecord->Edx += n;
		else if((bInstructionCache[0] & 0xF) == 0x3) ContextRecord->Ebx += n;
		else if((bInstructionCache[0] & 0xF) == 0x4) ContextRecord->Esp += n;
		else if((bInstructionCache[0] & 0xF) == 0x5) ContextRecord->Ebp += n;
		else if((bInstructionCache[0] & 0xF) == 0x6) ContextRecord->Esi += n; 
		else if((bInstructionCache[0] & 0xF) == 0x7) ContextRecord->Edi += n;
	
		*bIsVirtualInstruction = TRUE;
		return 1;
	}
	
	
	// vpush [reg32]
	if(bInstructionCache[0] >= V_PUSH_EAX && bInstructionCache[0] <= V_PUSH_EBP){
		#ifdef _DEBUG		
		printf("x86 emu : vpush\n");
		#endif		
		
		ContextRecord->Esp -= 4;
			 if((bInstructionCache[0] & 0xF) == 0x0) *(DWORD *)ContextRecord->Esp = ContextRecord->Eax;
		else if((bInstructionCache[0] & 0xF) == 0x1) *(DWORD *)ContextRecord->Esp = ContextRecord->Ecx;
		else if((bInstructionCache[0] & 0xF) == 0x2) *(DWORD *)ContextRecord->Esp = ContextRecord->Edx;
		else if((bInstructionCache[0] & 0xF) == 0x3) *(DWORD *)ContextRecord->Esp = ContextRecord->Ebx;
		else if((bInstructionCache[0] & 0xF) == 0x4) *(DWORD *)ContextRecord->Esp = ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x5) *(DWORD *)ContextRecord->Esp = ContextRecord->Ebp;
		else if((bInstructionCache[0] & 0xF) == 0x6) *(DWORD *)ContextRecord->Esp = ContextRecord->Esi;
		else if((bInstructionCache[0] & 0xF) == 0x7) *(DWORD *)ContextRecord->Esp = ContextRecord->Edi;
		*bIsVirtualInstruction = TRUE;
		return 1;
	}
	
	// vpop [reg32]
	else if(bInstructionCache[0] >= V_POP_EAX && bInstructionCache[0] <= V_POP_EBP){
		#ifdef _DEBUG		
		printf("x86 emu : vpop\n");
		#endif		  	 
		
			 if((bInstructionCache[0] & 0xF) == 0x0) ContextRecord->Eax = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x1) ContextRecord->Ecx = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x2) ContextRecord->Edx = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x3) ContextRecord->Ebx = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x4) ContextRecord->Esp = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x5) ContextRecord->Ebp = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x6) ContextRecord->Esi = *(DWORD *)ContextRecord->Esp;
		else if((bInstructionCache[0] & 0xF) == 0x7) ContextRecord->Edi = *(DWORD *)ContextRecord->Esp;
		ContextRecord->Esp += 4;
		*bIsVirtualInstruction = TRUE;
		return 1;
	}
	
	return nInstructionLen = x86opsize(bInstructionCache); // x86 instruction
}

int main(void)
{
	int nRet, n = 0;
	char szBuff[256];
	
	INSTALL_SEH(seh)
	__asm{
			xor ebx, ebx
		}
	P_CODE_START
		__asm{
			inc eax
			nop
			inc eax
			inc eax
			mov eax, ebx
			mov edx, eax
			mov n, edx
			nop
		}
	P_CODE_END
	printf("n = %d\n", n);

	
	UNINSTALL_SEH
	return 0;
}