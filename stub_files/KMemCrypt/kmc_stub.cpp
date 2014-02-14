/*=========================================
	KMemCrypt C Stub BETA V2.2 (C) KOrUPt
	
	This file is the stub of KMemCrypt coupled with an example usage(see main())
	This file should be compiled and the SEH handler ripped alongside the global
	variable's so it can be used with KInterface.
	
	See kmc_stub.asm for example
	
	Note that the pcode blocks are encrypted via kmc_encrypt_mem.cpp,
	this functionality is also carried out via CryptMem()
	
	NOTES:
		PCODE markers are designed to obfuscate code that may be detected
		as malicous by AV's. 
		
		Given the nature of the application, the following rules must be adhered to
		in order to ensure transparency:
			1. DO NOT WRAP DATA SUCH AS TEXT IN PCODE TAGS
			2. DO NOT PLACE A PCODE END MARKER IN A LOOP WITHOUT A PCODE START MARKER
				I.e pcode_start while(1) { pcode_end } will break your application
			3. ENSURE THAT FOR EVERY PCODE START MARKER, THERE IS A _LINEAR_ 
			   EXECUTION PATH TO A PCODE END MARKER(early function returns are allowed however)
			4. DO NOT NEST MORE THAN MAX_NESTED_CALLS
			5. DO NOT WRAP CPU INTENSIVE CODE THAT EXECUTES WITHIN A LOOP
			   IN PCODE TAGS, AS THIS MAY BE VERY SLOW
			6. ENSURE YOU DECLARE AT LEAST ONE LOCAL VARIABLE IN ALL FUNCTIONS
			   THAT USE PCODE MARKERS
				(this has to do with msvc optimizing functions that don't use local variable's)
			7. TURN _DEBUG OFF WHEN BUILDING A FINAL STUB
			
		References:
		http://thestarman.pcministry.com/asm/2bytejumps.htm
		http://www.c-jump.com/CIS77/ASM/Instructions/I77_0070_eflags_bits.htm
*/
#define WIN_32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x501
#pragma comment(linker,"/BASE:0x400000 /FILEALIGN:0x200 /MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,EWR /IGNORE:4078")
#pragma comment(lib,"Ws2_32.lib")
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <time.h>

#include "..\..\shared_files\x86opsize.cpp"
#include "..\..\shared_files\vopcodes.h"
#include "..\..\shared_files\x86opcodes.h"
#include "..\..\shared_files\KMemCryptP.h"

#define MAX_NESTED_CALLS 5
#define MAX_INSTRUCTION_LENGTH 16
#define Z_FLAG 0x40 // 0010 0000

// turn on verbose output
#define _DEBUG

#ifdef _DEBUG
// show all breakpoints
//#define SHOW_API_BREAKPOINTS				// set when an API is called
//#define SHOW_INTERMODULAR_BREAKPOINTS		// set when an local function is called
//#define SHOW_VINST_BREAKPOINTS			// set when a virtual instruction is hit
// breakpoint types
#define API_BREAKPOINT 1
#define INTERMODULAR_BREAKPOINT 2
#define VINST_BREAKPOINT 3
int nLastBreakpointType[MAX_NESTED_CALLS] = {0};
int nFirstLaunch = 1;
#endif

// globals - required by exception handler
DWORD 	dwOpcodeBackup[MAX_NESTED_CALLS];				
DWORD	*dwPrevInstructionAddr[MAX_NESTED_CALLS];
BYTE	bUsingVm[MAX_NESTED_CALLS] = {0};
int		nPrevInstructionLen[MAX_NESTED_CALLS];
int 	nNestingLevel	= 0;

// 1. in  - Decrypted instruction
// 2. out - Whether or not we emulated the instruction
// 3. out - Whether or not the instruction after the one emulated will be executed
// 4. in  - the context of the thread that produced the exception
int EnterVM(BYTE *bInstructionCache, BOOL *bIsVirtualInstruction, BOOL *bReturning, _CONTEXT *ContextRecord);

// the following is used to identify global varible's
// within the assembly of the stub
void SetGlobals(){
	__asm { 
		nop 
		nop 
		nop
		nop
	}
	
	dwOpcodeBackup[0] 				= 1;
	dwPrevInstructionAddr[0] 		= (DWORD *)0x2;
	nPrevInstructionLen[0] 			= 3;
	nNestingLevel 					= 4;
	bUsingVm[0]						= 5;

	__asm { 
		nop 
		nop 
		nop
		nop
	}
}

// our stub in its elegant C form
ULONG seh(_EXCEPTION_RECORD *ExceptionRecord, void *EstablisherFrame, _CONTEXT *ContextRecord, void * DispatcherContext)
{
	const int nImageBase	= 0x00400000; // hardcoded - to be updated by loader
	const BYTE bXorkey 		= 0xC3;		  // xor key constant
	BYTE  bInstructionCache[MAX_INSTRUCTION_LENGTH];
	DWORD dwBackedUpEip;
	DWORD dwDynImageBase	= ((DWORD)ExceptionRecord->ExceptionAddress & 0xFFFF0000);
	BYTE *lpByte;
	BOOL bIsVirtualInstruction, bReturning;
	int  i;
	
	#ifdef _DEBUG		
	if(nFirstLaunch){
		printf("------------- [%d] PCODE START\n", nNestingLevel);
		nFirstLaunch = 0;
	}
	#endif
	
	// if we hit our pcode end marker, we must clean up and exit
	if((*(BYTE *)(ContextRecord->Eip) ^ bXorkey) == OPCODE_IN){
		#ifdef _DEBUG
		if(bUsingVm[nNestingLevel])
			printf("------------- [%d] Switching off VM for this block\n", nNestingLevel);
		printf("------------- [%d] PCODE END\n", nNestingLevel);
		nFirstLaunch = 1;
		#endif
		
		// skip broken instruction and turn off VM for this block
		ContextRecord->Eip += 1;	 		
		bUsingVm[nNestingLevel] = 0;		
		return EXCEPTION_CONTINUE_SEARCH;
	}
	
	// turn the trap flag back on
	ContextRecord->EFlags |= 0x100;
	
	// we hit an injected breakpoint, so restore context
	if(ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT && dwDynImageBase == nImageBase){
		// decrement nesting level
		if(nNestingLevel > 0) nNestingLevel--;
		
		#ifdef _DEBUG
		switch(nLastBreakpointType[nNestingLevel]){
			case API_BREAKPOINT:
				#ifdef SHOW_API_BREAKPOINTS
				printf("------------- [%d] API breakpoint removed @ 0x%08X\n", nNestingLevel, ExceptionRecord->ExceptionAddress);
				#endif
				break;
			case INTERMODULAR_BREAKPOINT:
				#ifdef SHOW_INTERMODULAR_BREAKPOINTS
				printf("------------- [%d] Intermodular breakpoint removed @ 0x%08X\n", nNestingLevel, ExceptionRecord->ExceptionAddress);
				#endif
				break;
			case VINST_BREAKPOINT:
				#ifdef SHOW_VINST_BREAKPOINTS
				printf("------------- [%d] VInstruction breakpoint removed @ 0x%08X\n", nNestingLevel, ExceptionRecord->ExceptionAddress);
				#endif
				break;
			default:
				printf("------------- [%d] Unknown breakpoint removed @ 0x%08X\n", nNestingLevel, ExceptionRecord->ExceptionAddress);
		}
		#endif
		
		// restore instruction
		*(DWORD *)(ExceptionRecord->ExceptionAddress) = dwOpcodeBackup[nNestingLevel];
		
		// after we've restored an instruction,
		// we can encrypt the old instructions
		// and decrypt the new ones
		goto _DecryptInstruction;
	}
	
	// the trap flag is on, so we continue to decrypt routines
	if(ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP){
		// are we calling a function outside of this module? Perhaps an API?
		// if so, set an API breakpoint at return address and allow API to execute
		if(dwDynImageBase != nImageBase){
			DWORD dwRetAddress			  = *(DWORD *)(ContextRecord->Esp); // get caller return address
			dwOpcodeBackup[nNestingLevel] = *(DWORD *)(dwRetAddress);		// save opcode at the return address
			*(BYTE *)(dwRetAddress) 	  = OPCODE_BREAKPOINT; 				// set breakpoint at return address
			
			#ifdef _DEBUG
			nLastBreakpointType[nNestingLevel] = API_BREAKPOINT;
			#ifdef SHOW_API_BREAKPOINTS
			printf("------------- [%d] API breakpoint set @ 0x%08X\n", nNestingLevel, dwRetAddress);
			#endif
			#endif
			
			// this counter is decremented by our breakpoint handler
			// so increase it in order to keep numbers correct
			if(nNestingLevel < MAX_NESTED_CALLS) nNestingLevel++;
			
			// turn trap flag off as we don't want to step through an external routine
			ContextRecord->EFlags &= !0x100;
			return EXCEPTION_CONTINUE_SEARCH;
		}
		
		// handle intermodular calls
		if((*(BYTE *)(ContextRecord->Eip) ^ bXorkey) == OPCODE_CALL){
			// call instruction is 5 bytes
			DWORD  dwRetAddress = (ContextRecord->Eip + 5);	
				
			#ifdef _DEBUG
			nLastBreakpointType[nNestingLevel] = INTERMODULAR_BREAKPOINT;
			#ifdef SHOW_INTERMODULAR_BREAKPOINTS
			printf("------------- [%d] Intermodulular breakpoint set @ 0x%08X(0x%02X)\n", nNestingLevel, dwRetAddress, (*(BYTE *)(dwRetAddress) ^ bXorkey));
			#endif
			#endif
			
			// save opcode at the return address
			dwOpcodeBackup[nNestingLevel] = *(DWORD *)(dwRetAddress);
			// overwrite it with a breakpoint
			*(BYTE *)(dwRetAddress) = OPCODE_BREAKPOINT;
			
			// turn off trap flag
			ContextRecord->EFlags &= !0x100;
			
			// nesting level is increased after the following decryption of instructions
			// we'll re-activate once we hit the breakpoint
		}
		
		_DecryptInstruction:		
		lpByte = (BYTE *)ContextRecord->Eip;
		// cache & decrypt current instructions
		for(i = 0; i < 16; i++) 
			bInstructionCache[i] = *(lpByte + i) ^ bXorkey;
		
		// encrypt previous instructions
		if(nPrevInstructionLen[nNestingLevel] > 0){
			lpByte = (BYTE *)dwPrevInstructionAddr[nNestingLevel], i = nPrevInstructionLen[nNestingLevel];
			while(i--){
				*(lpByte + i) ^= bXorkey;
			}	
		}
		
		// check for unencrypted epilog:
			// mov esp, ebp; pop ebp; ret
		// we don't want to decrypt non-encrypted epilogs so return early.
		// This situation is encountered if we return from a function whilist
		// within pcode macro's(see #kmbc3), where the compiler inserts a jmp
		// to the function epilog outside of the pcode macro's
		if(*(DWORD *)(ContextRecord->Eip) == X86_FUNC_EPILOG){
			#ifdef _DEBUG
			printf("------------- Abrupt function exit due to epilog jump\n");
			#endif

			ContextRecord->EFlags				&= !0x100;
			nPrevInstructionLen[nNestingLevel]	= 0;
			bUsingVm[nNestingLevel] 			= 0;	
			return EXCEPTION_CONTINUE_SEARCH;	// do not attempt to decrypt!
		}
		
		// store address of this [will be previous] instruction
		dwPrevInstructionAddr[nNestingLevel] = (DWORD *)ContextRecord->Eip;
		// back up eip
		dwBackedUpEip = ContextRecord->Eip;
		// x86 code emulator, emulates x86 instructions, returns instruction length
		nPrevInstructionLen[nNestingLevel] = i = EnterVM(bInstructionCache, &bIsVirtualInstruction, &bReturning, ContextRecord);
		// was the instruction emulated?
		if(bIsVirtualInstruction == TRUE){
			#ifdef _DEBUG		
			printf("------------- eip: 0x%08X(vm): ", (dwBackedUpEip));
			for(int x = 0; x < i; x++)
				printf("%02X ", (*(BYTE *)(dwBackedUpEip + x) ^ bXorkey));
			printf("\n");
			#endif
			
			// we don't decrypt instructions here so there is nothing to re-encrypt
			nPrevInstructionLen[nNestingLevel] = 0;
			
			// place breakpoint AFTER virtual instruction
			// provided we'll hit it/return onto it.
			// triggered for most instructions including
			// near call as we return after the call has 
			// executed
			if(bReturning){
				#ifdef _DEBUG
				nLastBreakpointType[nNestingLevel] = VINST_BREAKPOINT;
				#ifdef SHOW_VINST_BREAKPOINTS
				printf("------------- Current EIP: 0x%08X (%02X)\n------------- Instruction length: %d\n------------- New EIP: 0x%08X (%02X)\n", dwBackedUpEip, *(BYTE *)(dwBackedUpEip) ^ bXorkey, i, dwBackedUpEip + i, *(BYTE *)(dwBackedUpEip + i) ^ bXorkey);
				printf("------------- [%d] VInstruction breakpoint set @ 0x%08X\n", nNestingLevel, (dwBackedUpEip + i));
				#endif
				#endif
				
				// backup opcode and set breakpoint
				dwOpcodeBackup[nNestingLevel] 		= *(DWORD *)(dwBackedUpEip + i); 
				*(BYTE *)(dwBackedUpEip + i) 		= OPCODE_BREAKPOINT;
				// increment nested call stack if we're about to make a call
				// as called function may contain pcode blocks also
				if(nNestingLevel < MAX_NESTED_CALLS) nNestingLevel++;
				// turn off trap flag
				ContextRecord->EFlags &= !0x100;
			}
			
			// we're not returning to the next instruction,
			// means we've emulated a short jmp, jge, jnz, je or similar
			// to another address inside our pcode, so set breakpoint
			// at that address instead
			else{
				#ifdef _DEBUG
				nLastBreakpointType[nNestingLevel] = VINST_BREAKPOINT;
				#ifdef SHOW_VINST_BREAKPOINTS
				printf("------------- Current EIP: 0x%08X (%02X)\n------------- Instruction length: %d\n------------- JMP EIP: 0x%08X (%02X)\n", dwBackedUpEip, *(BYTE *)(dwBackedUpEip) ^ bXorkey, i, ContextRecord->Eip, *(BYTE *)(ContextRecord->Eip) ^ bXorkey);
				printf("------------- [%d] VInstruction breakpoint set @ 0x%08X\n", nNestingLevel, ContextRecord->Eip);
				#endif
				#endif
				
				// backup opcode and set breakpoint
				dwOpcodeBackup[nNestingLevel] 		= *(DWORD *)(ContextRecord->Eip); 
				*(BYTE *)(ContextRecord->Eip) 		= OPCODE_BREAKPOINT;
				// our breakpoint handler decrements this upon restore,
				// so increment it to balance the numbers
				if(nNestingLevel < MAX_NESTED_CALLS) nNestingLevel++;
				// turn off trap flag
				ContextRecord->EFlags &= !0x100;
			}
			
			// increment eip so instruction is skipped,
			// provided we haven't emulated a 
			// near call, jmp, je, jnz, jbe or jge
			// as they would change eip to the  
			// address called/jmp'd to
			if(dwBackedUpEip == ContextRecord->Eip){
				ContextRecord->Eip += i;
			}
				
			// continue execution without decrypting
			return EXCEPTION_CONTINUE_SEARCH;	
		}
		
		// increment nested call stack if we're about to make a call
		// as the called function may contain pcode blocks
		if((*(BYTE *)(ContextRecord->Eip) ^ bXorkey) == OPCODE_CALL){
			if(nNestingLevel < MAX_NESTED_CALLS) nNestingLevel++;
		}
		
		// decrypt and execute instruction
		#ifdef _DEBUG		
		printf("------------- eip: 0x%08X(x86): ", (ContextRecord->Eip));
		for(int x = 0; x < i; x++)
			printf("%02X ", (*(BYTE *)(ContextRecord->Eip + x) ^ bXorkey));
		printf("\n");
		#endif
		
		while(i--){
			*(BYTE *)(ContextRecord->Eip + i) ^= bXorkey;
		}
	}
	
	// resume execution
	return EXCEPTION_CONTINUE_SEARCH;
}

// handle's virtual instructions and serves as a wrapper for the LDE
int EnterVM(BYTE *bInstructionCache, BOOL *bIsVirtualInstruction, BOOL *bReturning, _CONTEXT *ContextRecord)
{
	// presume min instruction length = 1
	int nInstructionLen = 1, n = 0;
	// assume instruction is x86 by default
	*bIsVirtualInstruction = FALSE;
	// whether or not we'll execute the instruction after this one
	// this value is false for jmp's for example but true for call's
	// as we'll eventually hit the instruction once we return
	// from the call, which is not the case for jmp's
	*bReturning = TRUE;
	
	// is this code block using a vm
	if(*(DWORD *)(bInstructionCache) == 0xDDCCBBAA){
		#ifdef _DEBUG		
		printf("------------- [%d] Using VM for this block\n", nNestingLevel);
		#endif
		
		// turn on VM
		bUsingVm[nNestingLevel] = 1;
		*bIsVirtualInstruction = TRUE;
		return 4;
	}
	
	// skip vm handlers if we're not using a vm
	if(!bUsingVm[nNestingLevel])
		goto no_vm;
	
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
	
		DWORD dwAddress = ContextRecord->Eip + 5;	// compute return address
		ContextRecord->Esp -= 4;				  	// adjust stack
		*(DWORD *)ContextRecord->Esp = dwAddress; 	// push return address
		dwAddress += *(DWORD *)(bInstructionCache + 1) ^ 0x10203040; // calc address
		ContextRecord->Eip = dwAddress;			  	// set eip to address
		*bIsVirtualInstruction = TRUE;	
		return 5;
	}
	
	if(bInstructionCache[0] == V_SHORT_JMP){
		#ifdef _DEBUG		
		printf("x86 emu : vsjmp\n");
		#endif
		
		DWORD dwAddress = (ContextRecord->Eip + 2) + (*(signed char *)(bInstructionCache + 1) ^ 0x10);
		ContextRecord->Eip = dwAddress;			   // set eip to address
		*bIsVirtualInstruction = TRUE;
		*bReturning = FALSE;
		#ifdef _DEBUG		
		printf("jumping to %08X\n", dwAddress);
		#endif
		return 2;
	}
	
	if(bInstructionCache[0] == V_SHORT_JE){
		#ifdef _DEBUG		
		printf("x86 emu : vsje\n");
		#endif
		
		// if z flag is set, then jump
		if((ContextRecord->EFlags & Z_FLAG)){
			DWORD dwAddress = (ContextRecord->Eip + 2) + (*(signed char *)(bInstructionCache + 1) ^ 0x10);
			ContextRecord->Eip = dwAddress;			// set eip to address
			*bReturning = FALSE;
			#ifdef _DEBUG		
			printf("jumping to %08X\n", dwAddress);
			#endif
		}
		
		#ifdef _DEBUG		
		else printf("not jumping\n");
		#endif
		
		// if z flag isn't set, do nothing, just skip
		*bIsVirtualInstruction = TRUE;
		return 2;
	}
	
	if(bInstructionCache[0] == V_SHORT_JNZ){
		#ifdef _DEBUG		
		printf("x86 emu : vsjnz\n");
		#endif
		
		// if z flag is NOT set, then jump
		if(!(ContextRecord->EFlags & Z_FLAG)){
			DWORD dwAddress = (ContextRecord->Eip + 2) + (*(signed char *)(bInstructionCache + 1) ^ 0x10);
			ContextRecord->Eip = dwAddress;
			*bReturning = FALSE;
			#ifdef _DEBUG		
			printf("jumping to %08X\n", dwAddress);
			#endif
		}
		
		// if z flag is set, do nothing, just skip
		*bIsVirtualInstruction = TRUE;
		return 2;
	}
	
	// vneg [r32]
	if(bInstructionCache[0] == V_NEG32 && (bInstructionCache[1] & 0xF0) == 0xD0){
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
	
	no_vm:
	return nInstructionLen = x86opsize(bInstructionCache); // x86 instruction
}

int AskQuestion(char *szMessage){
	int nChoice;
	P_CODE_START
	nChoice = MessageBox(HWND_DESKTOP, szMessage, "Greetings", MB_OK | MB_YESNO);
	P_CODE_END
	return nChoice;
}

int main(void)
{
	INSTALL_SEH(seh)
	char *szWelcome = "Would you like to answer this survey?";
	char *q1 		= "Are VM's cool?";
	char *q2 		= "What about me, am I cool?";
	
	char *thankyou	= "RIGHT ANSWER!";
	char *loose 	= "You lost, try again?";
	char *win		= "Well done, you've won! Try again?";
	
	printf("In main()\n");
	
	P_CODE_START
	P_CODE_USE_VM
		__asm{
			
			_startSurvey:
			mov eax, szWelcome
			mov ebx, eax
			push ebx
			call AskQuestion
			cmp eax, IDYES
			je _q1
			jmp _loose
			
			_q1:
			mov eax, q1
			push eax
			call AskQuestion
			cmp eax, IDYES
			je _q2
			jmp _loose
			
			_q2:
			mov eax, q2
			push eax
			call AskQuestion
			cmp eax, IDYES
			jnz _q2
			
			mov eax, thankyou
			push eax
			call AskQuestion
			jmp _win
		
			// if they don't answer yes, loop
			_loose:
			nop
			mov eax, loose
			push eax
			call AskQuestion
			cmp eax, IDYES
			jnz _loose
			jmp _startSurvey
			
			_win:
			mov eax, win
			push eax
			call AskQuestion
			cmp eax, IDYES
			je _startSurvey
			nop
		}
	P_CODE_END

	UNINSTALL_SEH
	return 0;
}