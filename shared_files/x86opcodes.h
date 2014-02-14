// contains x86 definitions for encoder
// generic
#define	X86_NOP 	  0x90
// addition
#define X86_INC_EAX 0x40
#define X86_INC_ECX 0x41
#define X86_INC_EDX 0x42
#define X86_INC_EBX 0x43
#define X86_INC_ESP 0x44
#define X86_INC_EBP 0x45
#define X86_INC_ESI 0x46
#define X86_INC_EDI 0x47
// subtraction
#define X86_DEC_EAX 0x48
#define X86_DEC_ECX 0x49
#define X86_DEC_EDX 0x4A
#define X86_DEC_EBX 0x4B
#define X86_DEC_ESP 0x4C
#define X86_DEC_EBP 0x4D
#define X86_DEC_ESI 0x4E
#define X86_DEC_EDI 0x4F

// stack management
// push [reg32]
#define X86_PUSH_EAX 0x50
#define X86_PUSH_ECX 0x51
#define X86_PUSH_EDX 0x52
#define X86_PUSH_EBX 0x53
#define X86_PUSH_ESP 0x54
#define X86_PUSH_EBP 0x55
#define X86_PUSH_ESI 0x56
#define X86_PUSH_EDI 0x57
// pop [reg32]
#define X86_POP_EAX 0x58
#define X86_POP_ECX 0x59
#define X86_POP_EDX 0x5A
#define X86_POP_EBX 0x5B
#define X86_POP_ESP 0x5C
#define X86_POP_EBP 0x5D
#define X86_POP_ESI 0x5E
#define X86_POP_EDI 0x5F
// vmov [reg32], [reg32]
#define X86_MOV32   0x8B
// vadd [reg32], [reg32]
#define X86_ADD32	  0x03 // < takes the form of mov r32, r32
// vneg [reg32]
#define X86_NEG32   0xF7 // < takes the form of add r32, r32
// vxor [reg32], [decimal constant]
#define X86_XOR32   0x83 // < takes the form of neg reg32

// flow control
#define X86_NEAR_CALL	0xE8
#define X86_SHORT_JMP	0xEB
#define X86_SHORT_JE		0x74
#define X86_SHORT_JNZ	0x75
#define X86_SHORT_JGE	0x7D
#define X86_SHORT_JBE	0x76
//-----------------------------------
// vmov eax, [vreg])
#define X86_MOV_EAX_EAX 0xC0
#define X86_MOV_EAX_ECX 0xC1
#define X86_MOV_EAX_EDX 0xC2
#define X86_MOV_EAX_EBX 0xC3
#define X86_MOV_EAX_ESP 0xC4
#define X86_MOV_EAX_EBP 0xC5
#define X86_MOV_EAX_ESI 0xC6
#define X86_MOV_EAX_EDI 0xC7
// vmov ecx, [vreg])
#define X86_MOV_ECX_EAX 0xC8
#define X86_MOV_ECX_ECX 0xC9
#define X86_MOV_ECX_EDX 0xCA
#define X86_MOV_ECX_EBX 0xCB
#define X86_MOV_ECX_ESP 0xCC
#define X86_MOV_ECX_EBP 0xCD
#define X86_MOV_ECX_ESI 0xCE
#define X86_MOV_ECX_EDI 0xCF
// vmov edx, [vreg]) 
#define X86_MOV_EDX_EAX 0xD0
#define X86_MOV_EDX_ECX 0xD1
#define X86_MOV_EDX_EDX 0xD2
#define X86_MOV_EDX_EBX 0xD3
#define X86_MOV_EDX_ESP 0xD4
#define X86_MOV_EDX_EBP 0xD5
#define X86_MOV_EDX_ESI 0xD6
#define X86_MOV_EDX_EDI 0xD7
// vmov ebx, [vreg]) 
#define X86_MOV_EBX_EAX 0xD8
#define X86_MOV_EBX_ECX 0xD9
#define X86_MOV_EBX_EDX 0xDA
#define X86_MOV_EBX_EBX 0xDB
#define X86_MOV_EBX_ESP 0xDC
#define X86_MOV_EBX_EBP 0xDD
#define X86_MOV_EBX_ESI 0xDE
#define X86_MOV_EBX_EDI 0xDF
// vmov esp, [vreg]) 
#define X86_MOV_ESP_EAX 0xE0
#define X86_MOV_ESP_ECX 0xE1
#define X86_MOV_ESP_EDX 0xE2
#define X86_MOV_ESP_EBX 0xE3
#define X86_MOV_ESP_ESP 0xE4
#define X86_MOV_ESP_EBP 0xE5
#define X86_MOV_ESP_ESI 0xE6
#define X86_MOV_ESP_EDI 0xE7
// vmov ebp, [vreg]) 
#define X86_MOV_EBP_EAX 0xE8
#define X86_MOV_EBP_ECX 0xE9
#define X86_MOV_EBP_EDX 0xEA
#define X86_MOV_EBP_EBX 0xEB
#define X86_MOV_EBP_ESP 0xEC
#define X86_MOV_EBP_EBP 0xED
#define X86_MOV_EBP_ESI 0xEE
#define X86_MOV_EBP_EDI 0xEF
// vmov esi, [vreg]) 
#define X86_MOV_ESI_EAX 0xF0
#define X86_MOV_ESI_ECX 0xF1
#define X86_MOV_ESI_EDX 0xF2
#define X86_MOV_ESI_EBX 0xF3
#define X86_MOV_ESI_ESP 0xF4
#define X86_MOV_ESI_EBP 0xF5
#define X86_MOV_ESI_ESI 0xF6
#define X86_MOV_ESI_EDI 0xF7
// vmov edi, [vreg]) 
#define X86_MOV_EDI_EAX 0xF8
#define X86_MOV_EDI_ECX 0xF9
#define X86_MOV_EDI_EDX 0xFA
#define X86_MOV_EDI_EBX 0xFB
#define X86_MOV_EDI_ESP 0xFC
#define X86_MOV_EDI_EBP 0xFD
#define X86_MOV_EDI_ESI 0xFE
#define X86_MOV_EDI_EDI 0xFF

// addition
// vadd eax, [vreg]
#define X86_ADD_EAX_EAX 0xC0
#define X86_ADD_EAX_ECX 0xC1
#define X86_ADD_EAX_EDX 0xC2
#define X86_ADD_EAX_EBX 0xC3
#define X86_ADD_EAX_ESP 0xC4
#define X86_ADD_EAX_EBP 0xC5
#define X86_ADD_EAX_ESI 0xC6
#define X86_ADD_EAX_EDI 0xC7
// vadd ecx, [vreg]
#define X86_ADD_ECX_EAX 0xC8
#define X86_ADD_ECX_ECX 0xC9
#define X86_ADD_ECX_EDX 0xCA
#define X86_ADD_ECX_EBX 0xCB
#define X86_ADD_ECX_ESP 0xCC
#define X86_ADD_ECX_EBP 0xCD
#define X86_ADD_ECX_ESI 0xCE
#define X86_ADD_ECX_EDI 0xCF
// vadd edx, [vreg]
#define X86_ADD_EDX_EAX 0xD0
#define X86_ADD_EDX_ECX 0xD1
#define X86_ADD_EDX_EDX 0xD2
#define X86_ADD_EDX_EBX 0xD3
#define X86_ADD_EDX_ESP 0xD4
#define X86_ADD_EDX_EBP 0xD5
#define X86_ADD_EDX_ESI 0xD6
#define X86_ADD_EDX_EDI 0xD7
// vadd ebx, [vreg]
#define X86_ADD_EBX_EAX 0xD8
#define X86_ADD_EBX_ECX 0xD9
#define X86_ADD_EBX_EDX 0xDA
#define X86_ADD_EBX_EBX 0xDB
#define X86_ADD_EBX_ESP 0xDC
#define X86_ADD_EBX_EBP 0xDD
#define X86_ADD_EBX_ESI 0xDE
#define X86_ADD_EBX_EDI 0xDF
// vadd esp, [vreg] 
#define X86_ADD_ESP_EAX 0xE0
#define X86_ADD_ESP_ECX 0xE1
#define X86_ADD_ESP_EDX 0xE2
#define X86_ADD_ESP_EBX 0xE3
#define X86_ADD_ESP_ESP 0xE4
#define X86_ADD_ESP_EBP 0xE5
#define X86_ADD_ESP_ESI 0xE6
#define X86_ADD_ESP_EDI 0xE7
// vadd ebp, [vreg]
#define X86_ADD_EBP_EAX 0xE8
#define X86_ADD_EBP_ECX 0xE9
#define X86_ADD_EBP_EDX 0xEA
#define X86_ADD_EBP_EBX 0xEB
#define X86_ADD_EBP_ESP 0xEC
#define X86_ADD_EBP_EBP 0xED
#define X86_ADD_EBP_ESI 0xEE
#define X86_ADD_EBP_EDI 0xEF
// vadd esi, [vreg]
#define X86_ADD_ESI_EAX 0xF0
#define X86_ADD_ESI_ECX 0xF1
#define X86_ADD_ESI_EDX 0xF2
#define X86_ADD_ESI_EBX 0xF3
#define X86_ADD_ESI_ESP 0xF4
#define X86_ADD_ESI_EBP 0xF5
#define X86_ADD_ESI_ESI 0xF6
#define X86_ADD_ESI_EDI 0xF7
// vadd edi, [vreg]
#define X86_ADD_EDI_EAX 0xF8
#define X86_ADD_EDI_ECX 0xF9
#define X86_ADD_EDI_EDX 0xFA
#define X86_ADD_EDI_EBX 0xFB
#define X86_ADD_EDI_ESP 0xFC
#define X86_ADD_EDI_EBP 0xFD
#define X86_ADD_EDI_ESI 0xFE
#define X86_ADD_EDI_EDI 0xFF
// vneg [vreg]
#define X86_NEG_EAX 0xD8
#define X86_NEG_ECX 0xD9
#define X86_NEG_EDX 0xDA
#define X86_NEG_EBX 0xDB
#define X86_NEG_ESP 0xDC
#define X86_NEG_EBP 0xDD
#define X86_NEG_ESI 0xDE
#define X86_NEG_EDI 0xDF
// vxor [vreg]
#define X86_XOR_EAX 0xF0
#define X86_XOR_ECX 0xF1
#define X86_XOR_EDX 0xF2
#define X86_XOR_EBX 0xF3
#define X86_XOR_ESP 0xF4
#define X86_XOR_EBP 0xF5
#define X86_XOR_ESI 0xF6
#define X86_XOR_EDI 0xF7

// x86 opcodes
#define OPCODE_NOP 0x90
#define OPCODE_HLT 0xF4
#define OPCODE_RET 0xC3
#define OPCODE_CALL 0xE8
#define OPCODE_BREAKPOINT 0xCC
#define OPCODE_INT2D 0xD2C2
#define OPCODE_IN 0xED
#define OPCODE_POPFD 0x9D
#define X86_FUNC_EPILOG 0xC35DE58B
