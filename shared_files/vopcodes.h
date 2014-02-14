// V1.1
// --- virtual opcodes ---
// contains definitions for virtual instruction set

// generic
#define	V_NOP 	  0xAA
// addition
#define V_INC_EAX 0x10
#define V_INC_ECX 0x11
#define V_INC_EDX 0x12
#define V_INC_EBX 0x13
#define V_INC_ESP 0x14
#define V_INC_EBP 0x15
#define V_INC_ESI 0x16
#define V_INC_EDI 0x17
// subtraction
#define V_DEC_EAX 0x20
#define V_DEC_ECX 0x21
#define V_DEC_EDX 0x22
#define V_DEC_EBX 0x23
#define V_DEC_ESP 0x24
#define V_DEC_EBP 0x25
#define V_DEC_ESI 0x26
#define V_DEC_EDI 0x27
// push [reg32]
#define V_PUSH_EAX 0x70
#define V_PUSH_ECX 0x71
#define V_PUSH_EDX 0x72
#define V_PUSH_EBX 0x73
#define V_PUSH_ESP 0x74 // JE = 0x54
#define V_PUSH_EBP 0x75 // JNZ = 0x56
#define V_PUSH_ESI 0x76
#define V_PUSH_EDI 0x77
// pop [reg32]
#define V_POP_EAX 0x40
#define V_POP_ECX 0x41
#define V_POP_EDX 0x42
#define V_POP_EBX 0x43
#define V_POP_ESP 0x44
#define V_POP_EBP 0x45
#define V_POP_ESI 0x46
#define V_POP_EDI 0x47


// vmov [reg32], [reg32]
#define V_MOV32   0xA8
// vadd [reg32], [reg32]
#define V_ADD32	  0xB8 // < takes the form of mov r32, r32
// vneg [reg32]
#define V_NEG32   0x03 // < takes the form of add r32, r32
// vxor [reg32], [decimal constant]
#define V_XOR32   0xA7 // < takes the form of neg reg32
// vcall [relative offset]
#define V_NEAR_CALL	0x82 // < takes the form of xor32
#define V_SHORT_JMP	0xE8 // < takes the form of near call
#define V_SHORT_JE	0x54 // < takes the form of push esp
#define V_SHORT_JNZ	0x56 // < takes the form of push ebp
// --
#define V_SHORT_JGE	0x5D // < takes the form of pop ebp
#define V_SHORT_JBE	0x50 // < takes the form of push eax
//-----------------------------------
// vmov eax, [vreg])
#define V_MOV_EAX_EAX 0xC0
#define V_MOV_EAX_ECX 0xC1
#define V_MOV_EAX_EDX 0xC2
#define V_MOV_EAX_EBX 0xC3
#define V_MOV_EAX_ESP 0xC4
#define V_MOV_EAX_EBP 0xC5
#define V_MOV_EAX_ESI 0xC6
#define V_MOV_EAX_EDI 0xC7
// vmov ecx, [vreg])
#define V_MOV_ECX_EAX 0xC8
#define V_MOV_ECX_ECX 0xC9
#define V_MOV_ECX_EDX 0xCA
#define V_MOV_ECX_EBX 0xCB
#define V_MOV_ECX_ESP 0xCC
#define V_MOV_ECX_EBP 0xCD
#define V_MOV_ECX_ESI 0xCE
#define V_MOV_ECX_EDI 0xCF
// vmov edx, [vreg]) 
#define V_MOV_EDX_EAX 0xD0
#define V_MOV_EDX_ECX 0xD1
#define V_MOV_EDX_EDX 0xD2
#define V_MOV_EDX_EBX 0xD3
#define V_MOV_EDX_ESP 0xD4
#define V_MOV_EDX_EBP 0xD5
#define V_MOV_EDX_ESI 0xD6
#define V_MOV_EDX_EDI 0xD7
// vmov ebx, [vreg]) 
#define V_MOV_EBX_EAX 0xD8
#define V_MOV_EBX_ECX 0xD9
#define V_MOV_EBX_EDX 0xDA
#define V_MOV_EBX_EBX 0xDB
#define V_MOV_EBX_ESP 0xDC
#define V_MOV_EBX_EBP 0xDD
#define V_MOV_EBX_ESI 0xDE
#define V_MOV_EBX_EDI 0xDF
// vmov esp, [vreg]) 
#define V_MOV_ESP_EAX 0xE0
#define V_MOV_ESP_ECX 0xE1
#define V_MOV_ESP_EDX 0xE2
#define V_MOV_ESP_EBX 0xE3
#define V_MOV_ESP_ESP 0xE4
#define V_MOV_ESP_EBP 0xE5
#define V_MOV_ESP_ESI 0xE6
#define V_MOV_ESP_EDI 0xE7
// vmov ebp, [vreg]) 
#define V_MOV_EBP_EAX 0xE8
#define V_MOV_EBP_ECX 0xE9
#define V_MOV_EBP_EDX 0xEA
#define V_MOV_EBP_EBX 0xEB
#define V_MOV_EBP_ESP 0xEC
#define V_MOV_EBP_EBP 0xED
#define V_MOV_EBP_ESI 0xEE
#define V_MOV_EBP_EDI 0xEF
// vmov esi, [vreg]) 
#define V_MOV_ESI_EAX 0xF0
#define V_MOV_ESI_ECX 0xF1
#define V_MOV_ESI_EDX 0xF2
#define V_MOV_ESI_EBX 0xF3
#define V_MOV_ESI_ESP 0xF4
#define V_MOV_ESI_EBP 0xF5
#define V_MOV_ESI_ESI 0xF6
#define V_MOV_ESI_EDI 0xF7
// vmov edi, [vreg]) 
#define V_MOV_EDI_EAX 0xF8
#define V_MOV_EDI_ECX 0xF9
#define V_MOV_EDI_EDX 0xFA
#define V_MOV_EDI_EBX 0xFB
#define V_MOV_EDI_ESP 0xFC
#define V_MOV_EDI_EBP 0xFD
#define V_MOV_EDI_ESI 0xFE
#define V_MOV_EDI_EDI 0xFF
// addition
// vadd eax, [vreg]
#define V_ADD_EAX_EAX 0xC0
#define V_ADD_EAX_ECX 0xC1
#define V_ADD_EAX_EDX 0xC2
#define V_ADD_EAX_EBX 0xC3
#define V_ADD_EAX_ESP 0xC4
#define V_ADD_EAX_EBP 0xC5
#define V_ADD_EAX_ESI 0xC6
#define V_ADD_EAX_EDI 0xC7
// vadd ecx, [vreg]
#define V_ADD_ECX_EAX 0xC8
#define V_ADD_ECX_ECX 0xC9
#define V_ADD_ECX_EDX 0xCA
#define V_ADD_ECX_EBX 0xCB
#define V_ADD_ECX_ESP 0xCC
#define V_ADD_ECX_EBP 0xCD
#define V_ADD_ECX_ESI 0xCE
#define V_ADD_ECX_EDI 0xCF
// vadd edx, [vreg]
#define V_ADD_EDX_EAX 0xD0
#define V_ADD_EDX_ECX 0xD1
#define V_ADD_EDX_EDX 0xD2
#define V_ADD_EDX_EBX 0xD3
#define V_ADD_EDX_ESP 0xD4
#define V_ADD_EDX_EBP 0xD5
#define V_ADD_EDX_ESI 0xD6
#define V_ADD_EDX_EDI 0xD7
// vadd ebx, [vreg]
#define V_ADD_EBX_EAX 0xD8
#define V_ADD_EBX_ECX 0xD9
#define V_ADD_EBX_EDX 0xDA
#define V_ADD_EBX_EBX 0xDB
#define V_ADD_EBX_ESP 0xDC
#define V_ADD_EBX_EBP 0xDD
#define V_ADD_EBX_ESI 0xDE
#define V_ADD_EBX_EDI 0xDF
// vadd esp, [vreg] 
#define V_ADD_ESP_EAX 0xE0
#define V_ADD_ESP_ECX 0xE1
#define V_ADD_ESP_EDX 0xE2
#define V_ADD_ESP_EBX 0xE3
#define V_ADD_ESP_ESP 0xE4
#define V_ADD_ESP_EBP 0xE5
#define V_ADD_ESP_ESI 0xE6
#define V_ADD_ESP_EDI 0xE7
// vadd ebp, [vreg]
#define V_ADD_EBP_EAX 0xE8
#define V_ADD_EBP_ECX 0xE9
#define V_ADD_EBP_EDX 0xEA
#define V_ADD_EBP_EBX 0xEB
#define V_ADD_EBP_ESP 0xEC
#define V_ADD_EBP_EBP 0xED
#define V_ADD_EBP_ESI 0xEE
#define V_ADD_EBP_EDI 0xEF
// vadd esi, [vreg]
#define V_ADD_ESI_EAX 0xF0
#define V_ADD_ESI_ECX 0xF1
#define V_ADD_ESI_EDX 0xF2
#define V_ADD_ESI_EBX 0xF3
#define V_ADD_ESI_ESP 0xF4
#define V_ADD_ESI_EBP 0xF5
#define V_ADD_ESI_ESI 0xF6
#define V_ADD_ESI_EDI 0xF7
// vadd edi, [vreg]
#define V_ADD_EDI_EAX 0xF8
#define V_ADD_EDI_ECX 0xF9
#define V_ADD_EDI_EDX 0xFA
#define V_ADD_EDI_EBX 0xFB
#define V_ADD_EDI_ESP 0xFC
#define V_ADD_EDI_EBP 0xFD
#define V_ADD_EDI_ESI 0xFE
#define V_ADD_EDI_EDI 0xFF
// vneg [vreg]
#define V_NEG_EAX 0xD8
#define V_NEG_ECX 0xD9
#define V_NEG_EDX 0xDA
#define V_NEG_EBX 0xDB
#define V_NEG_ESP 0xDC
#define V_NEG_EBP 0xDD
#define V_NEG_ESI 0xDE
#define V_NEG_EDI 0xDF
// vxor [vreg]
#define V_XOR_EAX 0xF0
#define V_XOR_ECX 0xF1
#define V_XOR_EDX 0xF2
#define V_XOR_EBX 0xF3
#define V_XOR_ESP 0xF4
#define V_XOR_EBP 0xF5
#define V_XOR_ESI 0xF6
#define V_XOR_EDI 0xF7

// internal instruction set macros
// byte
#define byte_type(x) __asm _emit x 
#define bb(x) __asm _emit x
// dword
#define dw(x) byte_type((x>>(0*8))&0xFF) byte_type((x>>(1*8))&0xFF)	byte_type((x>>(2*8))&0xFF) byte_type((x>>(3*8))&0xFF)
// word
#define ww(x) byte_type((x>>(0*8))&0xFF) byte_type((x>>(1*8))&0xFF)

// vinst([1 byte instruction])
// vinst([1 byte instruction])
#define vinst(x) bb(x)
// vmov(V_MOV_[reg32]_[reg32])
#define vmov(x) \
	bb(V_MOV32) \
	bb(x)
// vadd(V_ADD_[reg32]_[reg32])
#define vadd(x) \
	bb(V_ADD32) \
	bb(x)
// vneg(V_NEG_[reg32])
#define vneg(x) \
	bb(V_NEG32) \
	bb(x)
// vxor(V_XOR_[reg32], dwConstant)
#define vxor(register, dwConstant) \
	bb(V_XOR32)	\
	bb(register) \
	bb(dwConstant)
#define vcall(dwAddress) \
	bb(V_CALL) \
	dw(dwAddress)
// --- virtual opcodes ---
#define USE_VM 0x80000003