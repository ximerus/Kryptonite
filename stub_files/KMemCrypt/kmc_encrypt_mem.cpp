#pragma comment(lib, "dbghelp.lib")
#pragma comment(lib, "imagehlp.lib")
#include <windows.h>
#include <imagehlp.h>
#include <stdio.h>

#include "..\..\shared_files\FileMapper.h"
#include "..\..\shared_files\AddSection.h"
#include "..\..\shared_files\PEManipulator.h"

#include "..\..\shared_files\FileMapper.cpp"
#include "..\..\shared_files\AddSection.cpp"
#include "..\..\shared_files\PEManipulator.cpp"
#include "..\..\shared_files\x86opsize.cpp"
#include "..\..\shared_files\x86opcodes.h"
#include "..\..\shared_files\vopcodes.h"

//#define DONT_CRYPT

int VirtualizeMem(LPBYTE pStartSig, int nInstructionLen)
{
	int nInstructionsVirtualized = 0;
	if(nInstructionLen == 5){
		if(*(BYTE *)pStartSig == OPCODE_CALL){
			*pStartSig = V_NEAR_CALL;
			// obfuscate function address
			*(DWORD *)(pStartSig + 1) ^= 0x10203040;
			nInstructionsVirtualized++;
		}
	}
	
	if(nInstructionLen == 1){
		if(*(BYTE *)pStartSig >= X86_INC_EAX && *(BYTE *)pStartSig <= X86_INC_EDI){ 
			switch(*(BYTE *)pStartSig & 0xF){
				case 0x0: // inc eax
					*pStartSig = V_INC_EAX;
					nInstructionsVirtualized++;
					break;
				case 0x1: // inc ecx
					*pStartSig = V_INC_ECX;
					nInstructionsVirtualized++;
					break;
				case 0x2: // inc edx
					*pStartSig = V_INC_EDX;
					nInstructionsVirtualized++;
					break;
				case 0x3: // inc ebx
					*pStartSig = V_INC_EBX;
					nInstructionsVirtualized++;
					break;
				case 0x4: // inc esp
					*pStartSig = V_INC_ESP;
					nInstructionsVirtualized++;
					break;
				case 0x5: // inc ebp
					*pStartSig = V_INC_EBP;
					nInstructionsVirtualized++;
					break;
				case 0x6: // inc esi
					*pStartSig = V_INC_ESI;
					nInstructionsVirtualized++;
					break;
				case 0x7: // inc edi
					*pStartSig = V_INC_EDI;
					nInstructionsVirtualized++;
					break;
			}
		}
		
		if(*(BYTE *)pStartSig >= X86_DEC_EAX && *(BYTE *)pStartSig <= X86_DEC_EDI){ 
			switch(*(BYTE *)pStartSig & 0xF){
				case 0x8: // dec eax
					*pStartSig = V_DEC_EAX;
					nInstructionsVirtualized++;
					break;
				case 0x9: // dec ecx
					*pStartSig = V_DEC_ECX;
					nInstructionsVirtualized++;
					break;
				case 0xA: // dec edx
					*pStartSig = V_DEC_EDX;
					nInstructionsVirtualized++;
					break;
				case 0xB: // dec ebx
					*pStartSig = V_DEC_EBX;
					nInstructionsVirtualized++;
					break;
				case 0xC: // dec esp
					*pStartSig = V_DEC_ESP;
					nInstructionsVirtualized++;
					break;
				case 0xD: // dec ebp
					*pStartSig = V_DEC_EBP;
					nInstructionsVirtualized++;
					break;
				case 0xE: // dec esi
					*pStartSig = V_DEC_ESI;
					nInstructionsVirtualized++;
					break;
				case 0xF: // dec edi
					*pStartSig = V_DEC_EDI;
					nInstructionsVirtualized++;
					break;
			}
		}
		
		if(*(BYTE *)pStartSig >= X86_POP_EAX && *(BYTE *)pStartSig <= X86_POP_EDI){ 
			switch(*(BYTE *)pStartSig & 0xF){
				case 0x8: // pop eax
					*pStartSig = V_POP_EAX;
					nInstructionsVirtualized++;
					break;
				case 0x9: // pop ecx
					*pStartSig = V_POP_ECX;
					nInstructionsVirtualized++;
					break;
				case 0xA: // pop edx
					*pStartSig = V_POP_EDX;
					nInstructionsVirtualized++;
					break;
				case 0xB: // pop ebx
					*pStartSig = V_POP_EBX;
					nInstructionsVirtualized++;
					break;
				case 0xC: // pop esp
					*pStartSig = V_POP_ESP;
					nInstructionsVirtualized++;
					break;
				case 0xD: // pop ebp
					*pStartSig = V_POP_EBP;
					nInstructionsVirtualized++;
					break;
				case 0xE: // pop esi
					*pStartSig = V_POP_ESI;
					nInstructionsVirtualized++;
					break;
				case 0xF: // pop edi
					*pStartSig = V_POP_EDI;
					nInstructionsVirtualized++;
					break;
			}
		}
		
		if(*(BYTE *)pStartSig >= X86_PUSH_EAX && *(BYTE *)pStartSig <= X86_PUSH_EDI){ 
			switch(*(BYTE *)pStartSig & 0xF){
				case 0x0: // push eax
					*pStartSig = V_PUSH_EAX;
					nInstructionsVirtualized++;
					break;
				case 0x1: // push ecx
					*pStartSig = V_PUSH_ECX;
					nInstructionsVirtualized++;
					break;
				case 0x2: // push edx
					*pStartSig = V_PUSH_EDX;
					nInstructionsVirtualized++;
					break;
				case 0x3: // push ebx
					*pStartSig = V_PUSH_EBX;
					nInstructionsVirtualized++;
					break;
				case 0x4: // push esp
					*pStartSig = V_PUSH_ESP;
					nInstructionsVirtualized++;
					break;
				case 0x5: // push ebp
					*pStartSig = V_PUSH_EBP;
					nInstructionsVirtualized++;
					break;
				case 0x6: // push esi
					*pStartSig = V_PUSH_ESI;
					nInstructionsVirtualized++;
					break;
				case 0x7: // push edi
					*pStartSig = V_PUSH_EDI;
					nInstructionsVirtualized++;
					break;
			}
		}
	}else if(nInstructionLen == 2){
		if(*(BYTE *)pStartSig == X86_SHORT_JMP){
			*pStartSig = V_SHORT_JMP;
			// obfuscate function address
			*(BYTE *)(pStartSig + 1) ^= 0x10;
			nInstructionsVirtualized++;
		}
		
		if(*(BYTE *)pStartSig == X86_SHORT_JNZ){
			*pStartSig = V_SHORT_JNZ;
			// obfuscate function address
			*(BYTE *)(pStartSig + 1) ^= 0x10;
			nInstructionsVirtualized++;
		}
		
		if(*(BYTE *)pStartSig == X86_SHORT_JE){
			*pStartSig = V_SHORT_JE;
			// obfuscate function address
			*(BYTE *)(pStartSig + 1) ^= 0x10;
			nInstructionsVirtualized++;
		}
		
		if(*(BYTE *)pStartSig == X86_SHORT_JBE){
			*pStartSig = V_SHORT_JBE;
			// obfuscate function address
			*(BYTE *)(pStartSig + 1) ^= 0x10;
			nInstructionsVirtualized++;
		}
		
		if(*(BYTE *)pStartSig == X86_SHORT_JGE){
			*pStartSig = V_SHORT_JGE;
			// obfuscate function address
			*(BYTE *)(pStartSig + 1) ^= 0x10;
			nInstructionsVirtualized++;
		}
		
		if(*(BYTE *)pStartSig == X86_ADD32){
			// mov eax, r32
			*pStartSig = V_ADD32;
			// vadd eax, r32
			if(*(BYTE *)(pStartSig + 1) >= X86_ADD_EAX_EAX && *(BYTE *)(pStartSig + 1) <= X86_ADD_EAX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_ADD_EAX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_ADD_EAX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_ADD_EAX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_ADD_EAX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_ADD_EAX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_ADD_EAX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_ADD_EAX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_ADD_EAX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// vadd ecx, r32
			if(*(BYTE *)(pStartSig + 1) >= X86_ADD_ECX_EAX && *(BYTE *)(pStartSig + 1) <= X86_ADD_ECX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x8:
						*(pStartSig + 1) = V_ADD_EAX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x9:
						*(pStartSig + 1) = V_ADD_EAX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0xA:
						*(pStartSig + 1) = V_ADD_EAX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0xB:
						*(pStartSig + 1) = V_ADD_EAX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0xC:
						*(pStartSig + 1) = V_ADD_EAX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0xD:
						*(pStartSig + 1) = V_ADD_EAX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0xE: 
						*(pStartSig + 1) = V_ADD_EAX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0xF:
						*(pStartSig + 1) = V_ADD_EAX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// vadd edx, r32
			if(*(BYTE *)(pStartSig + 1) >= X86_ADD_EDX_EAX && *(BYTE *)(pStartSig + 1) <= X86_ADD_EDX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_ADD_EDX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_ADD_EDX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_ADD_EDX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_ADD_EDX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_ADD_EDX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_ADD_EDX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_ADD_EDX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_ADD_EDX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// vadd ebx, r32
			if(*(BYTE *)(pStartSig + 1) >= X86_ADD_EBX_EAX && *(BYTE *)(pStartSig + 1) <= X86_ADD_EBX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x8:
						*(pStartSig + 1) = V_ADD_EBX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x9:
						*(pStartSig + 1) = V_ADD_EBX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0xA:
						*(pStartSig + 1) = V_ADD_EBX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0xB:
						*(pStartSig + 1) = V_ADD_EBX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0xC:
						*(pStartSig + 1) = V_ADD_EBX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0xD:
						*(pStartSig + 1) = V_ADD_EBX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0xE: 
						*(pStartSig + 1) = V_ADD_EBX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0xF:
						*(pStartSig + 1) = V_ADD_EBX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// vadd esp, r32
			if(*(BYTE *)(pStartSig + 1) >= X86_ADD_ESP_EAX && *(BYTE *)(pStartSig + 1) <= X86_ADD_ESP_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_ADD_ESP_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_ADD_ESP_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_ADD_ESP_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_ADD_ESP_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_ADD_ESP_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_ADD_ESP_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_ADD_ESP_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_ADD_ESP_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// vadd ebp, r32
			if(*(BYTE *)(pStartSig + 1) >= X86_ADD_EBP_EAX && *(BYTE *)(pStartSig + 1) <= X86_ADD_EBP_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x8:
						*(pStartSig + 1) = V_ADD_EBP_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x9:
						*(pStartSig + 1) = V_ADD_EBP_ECX;
						nInstructionsVirtualized++;
						break;
					case 0xA:
						*(pStartSig + 1) = V_ADD_EBP_EDX;
						nInstructionsVirtualized++;
						break;
					case 0xB:
						*(pStartSig + 1) = V_ADD_EBP_EBX;
						nInstructionsVirtualized++;
						break;
					case 0xC:
						*(pStartSig + 1) = V_ADD_EBP_ESP;
						nInstructionsVirtualized++;
						break;
					case 0xD:
						*(pStartSig + 1) = V_ADD_EBP_EBP;
						nInstructionsVirtualized++;
						break;
					case 0xE: 
						*(pStartSig + 1) = V_ADD_EBP_ESI;
						nInstructionsVirtualized++;
						break;
					case 0xF:
						*(pStartSig + 1) = V_ADD_EBP_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
		}
	
		if(*(BYTE *)pStartSig == X86_MOV32){
			// mov eax, r32
			*pStartSig = V_MOV32;
			if(*(BYTE *)(pStartSig + 1) >= X86_MOV_EAX_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_EAX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_MOV_EAX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_MOV_EAX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_MOV_EAX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_MOV_EAX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_MOV_EAX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_MOV_EAX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_MOV_EAX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_MOV_EAX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// mov ecx, r32
			else if(*(BYTE *)(pStartSig + 1) >= X86_MOV_ECX_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_ECX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x8:
						*(pStartSig + 1) = V_MOV_ECX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x9:
						*(pStartSig + 1) = V_MOV_ECX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0xA:
						*(pStartSig + 1) = V_MOV_ECX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0xB:
						*(pStartSig + 1) = V_MOV_ECX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0xC:
						*(pStartSig + 1) = V_MOV_ECX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0xD:
						*(pStartSig + 1) = V_MOV_ECX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0xE: 
						*(pStartSig + 1) = V_MOV_ECX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0xF:
						*(pStartSig + 1) = V_MOV_ECX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// mov edx, r32
			else if(*(BYTE *)(pStartSig + 1) >= X86_MOV_EDX_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_EDX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_MOV_EDX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_MOV_EDX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_MOV_EDX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_MOV_EDX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_MOV_EDX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_MOV_EDX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_MOV_EDX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_MOV_EDX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// mov ebx, r32
			else if(*(BYTE *)(pStartSig + 1) >= X86_MOV_EBX_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_EBX_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x8:
						*(pStartSig + 1) = V_MOV_EBX_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x9:
						*(pStartSig + 1) = V_MOV_EBX_ECX;
						nInstructionsVirtualized++;
						break;
					case 0xA:
						*(pStartSig + 1) = V_MOV_EBX_EDX;
						nInstructionsVirtualized++;
						break;
					case 0xB:
						*(pStartSig + 1) = V_MOV_EBX_EBX;
						nInstructionsVirtualized++;
						break;
					case 0xC:
						*(pStartSig + 1) = V_MOV_EBX_ESP;
						nInstructionsVirtualized++;
						break;
					case 0xD:
						*(pStartSig + 1) = V_MOV_EBX_EBP;
						nInstructionsVirtualized++;
						break;
					case 0xE: 
						*(pStartSig + 1) = V_MOV_EBX_ESI;
						nInstructionsVirtualized++;
						break;
					case 0xF:
						*(pStartSig + 1) = V_MOV_EBX_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// mov esp, r32
			else if(*(BYTE *)(pStartSig + 1) >= X86_MOV_ESP_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_ESP_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_MOV_ESP_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_MOV_ESP_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_MOV_ESP_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_MOV_ESP_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_MOV_ESP_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_MOV_ESP_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_MOV_ESP_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_MOV_ESP_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
		
			// mov esi, r32
			else if(*(BYTE *)(pStartSig + 1) >= X86_MOV_ESI_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_ESI_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x0:
						*(pStartSig + 1) = V_MOV_ESI_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x1:
						*(pStartSig + 1) = V_MOV_ESI_ECX;
						nInstructionsVirtualized++;
						break;
					case 0x2:
						*(pStartSig + 1) = V_MOV_ESI_EDX;
						nInstructionsVirtualized++;
						break;
					case 0x3:
						*(pStartSig + 1) = V_MOV_ESI_EBX;
						nInstructionsVirtualized++;
						break;
					case 0x4:
						*(pStartSig + 1) = V_MOV_ESI_ESP;
						nInstructionsVirtualized++;
						break;
					case 0x5:
						*(pStartSig + 1) = V_MOV_ESI_EBP;
						nInstructionsVirtualized++;
						break;
					case 0x6: 
						*(pStartSig + 1) = V_MOV_ESI_ESI;
						nInstructionsVirtualized++;
						break;
					case 0x7:
						*(pStartSig + 1) = V_MOV_ESI_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
			
			// mov edi, r32
			else if(*(BYTE *)(pStartSig + 1) >= X86_MOV_EDI_EAX && *(BYTE *)(pStartSig + 1) <= X86_MOV_EDI_EDI){ 
				switch(*(BYTE *)(pStartSig + 1) & 0xF){
					case 0x8:
						*(pStartSig + 1) = V_MOV_EDI_EAX;
						nInstructionsVirtualized++;
						break;
					case 0x9:
						*(pStartSig + 1) = V_MOV_EDI_ECX;
						nInstructionsVirtualized++;
						break;
					case 0xA:
						*(pStartSig + 1) = V_MOV_EDI_EDX;
						nInstructionsVirtualized++;
						break;
					case 0xB:
						*(pStartSig + 1) = V_MOV_EDI_EBX;
						nInstructionsVirtualized++;
						break;
					case 0xC:
						*(pStartSig + 1) = V_MOV_EDI_ESP;
						nInstructionsVirtualized++;
						break;
					case 0xD:
						*(pStartSig + 1) = V_MOV_EDI_EBP;
						nInstructionsVirtualized++;
						break;
					case 0xE: 
						*(pStartSig + 1) = V_MOV_EDI_ESI;
						nInstructionsVirtualized++;
						break;
					case 0xF:
						*(pStartSig + 1) = V_MOV_EDI_EDI;
						nInstructionsVirtualized++;
						break;
				}
			}
		}			
	}
	
	return nInstructionsVirtualized;
}

int CryptMem(char *szTargetFile, DWORD dwFlags)
{
	LPMAPINFO lpTargetFile;
	PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_SECTION_HEADER lpSecHdr, lpSection;
	LPBYTE  pStartSig, pEndSig, pTemp;
	char 	*pszErrorMsg;
	int		nStatus = 0;
	
	int nInstructionsVirtualized =  0;
	int i = 0, nSigCount = 0, nTotalBytes = 0, nInstructionLen = 0;
	bool bPCodeTagFound = false, bVmTagFound = false;
	const int xorkey 				= 0xC3;
	
	// set error string in advance
	pszErrorMsg = "- Could not load target file";
	
	// load target file
	lpTargetFile = LoadFile(szTargetFile, NULL);
	if(lpTargetFile)
	{
		// check PE headers and make sure executable is 32bit
		if((pNtHeaders = ImageNtHeader(lpTargetFile->lpBuffer))){
			if(pNtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386){
				// check for executable sections
				lpSecHdr = IMAGE_FIRST_SECTION(pNtHeaders);
				for(int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++){
					// is section is executable?
					if(lpSecHdr->Characteristics & IMAGE_SCN_MEM_EXECUTE)
					{
						// set pointers to start and end of section
						LPBYTE lpStart = (lpTargetFile->lpBuffer + lpSecHdr->PointerToRawData);
						LPBYTE lpEnd   = (lpStart + lpSecHdr->SizeOfRawData);
						
						// make section readable and executable
						lpSecHdr->Characteristics = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;
						
						// search section byte by byte and locate start/end markers
						while(lpStart < lpEnd){
							// locate start marker
							if(!memcmp(lpStart, "\xDE\xAD\xC0\xDE", 4)){ 		     // start sig: 0xDEADC0DE
								// store start tag offset
								lpStart += 4; // skip start tag
								pStartSig = lpStart;
								
								// locate end tag
								while(lpStart < lpEnd){
									if(!memcmp(lpStart, "\xDE\xAD\xBE\xEF", 4)){	// end sig: 0xDEADBEEF
										// make a note that end tag was found
										bPCodeTagFound = true;
										break;
									}
									
									lpStart++;
								}
								
								// if we have an end tag, encrypt code inbetween tags
								if(bPCodeTagFound){
									pEndSig = lpStart; // store end tag offset
									
									// update status
									printf("[*] KMC: Encrypting %d bytes(pcode block %d)\n", 
										((DWORD)pEndSig - (DWORD)pStartSig), nSigCount + 1);
									
									// update statisitcal data
									nTotalBytes += ((DWORD)pEndSig - (DWORD)pStartSig);
									
									// erase start and end signature
									memset((pStartSig - 4), 0x90 ^ xorkey, 4);
									memset((pEndSig), 0x90, 4);
									
									// if we're using a vm then locate + encrypt vm_on switch
									if((dwFlags & USE_VM) == USE_VM){
										// find and encrypt vm_on switch
										pTemp = pStartSig;
										while(pTemp < pEndSig){
											if(!memcmp(pTemp, "\xAA\xBB\xCC\xDD", 4)){
												printf("[+] KMC: Found VM signature for pcode block %d\n", nSigCount + 1);
												// encrypt vm signature placeholder
												for(i = 0; i < 4; i++)
													*(pTemp + i) ^= xorkey;
												
												// skip this signature
												pStartSig += 4;
												// make a note that this pcode block uses a vm
												bVmTagFound = true;
											}
											
											pTemp++;
										}
										
										if(!bVmTagFound) printf("[-] KMC: Not using VM for pcode block %d\n", nSigCount + 1);
									}
									
									// xor code inbetween tags
									while(pStartSig < pEndSig){
										// get length of instruction to encrypt
										nInstructionLen = x86opsize(pStartSig);
										
										if((dwFlags & USE_VM) == USE_VM && bVmTagFound){
											nInstructionsVirtualized += VirtualizeMem(pStartSig, nInstructionLen);
										}
										
										#ifndef DONT_CRYPT 
										for(i = 0; i < nInstructionLen; i++)
											*(pStartSig + i) ^= xorkey;
										#endif
										
										pStartSig += nInstructionLen;
									}
									
									// incremenent encrypted block count and reset end tag identifier
									nSigCount++;
									bPCodeTagFound = false;
									bVmTagFound = false;
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
			}
		}
		
		pszErrorMsg = "+ File crypted!";
		FlushViewOfFile(lpTargetFile->lpBuffer, 0);
		UnloadFile(lpTargetFile);
	}

	printf("\n\n[*] KMC: Encrypted %d pcode blocks(%d bytes)\n[*] KMC: Virtualized %d instructions\n", nSigCount, nTotalBytes, nInstructionsVirtualized);
	printf("[%c] KMC: %s%s\n", pszErrorMsg[0], pszErrorMsg[0] == '-' ? " Error!" : " Success!", pszErrorMsg + 1);
	return nStatus;
}

int main(int argc, char **argv)
{
	int nStatus = 0;
	if(argc == 2)
		nStatus = CryptMem(argv[1], USE_VM);
	return nStatus;
}