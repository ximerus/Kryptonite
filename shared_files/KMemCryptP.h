// KMemCrypt protection macro's
// V1.1

// protection macros
#define bb(x) __asm _emit x
#define P_CODE_START	\
	__asm{pushfd}		\
	__asm{or dword ptr[esp], 100h} \
	__asm{popfd}		\
	bb(0xDE) bb(0xAD) bb(0xC0) bb(0xDE) \

#define P_CODE_END	\
	__asm{nop} \
	__asm{in eax, dx} \
	bb(0xDE) bb(0xAD) bb(0xBE) bb(0xEF)

#define P_CODE_INSTALL_SEH  \
	bb(0xCA) bb(0xFE) bb(0xBA) bb(0xBE) \
	__asm{mov eax, 0xCCCCCCCC}   \
	__asm{push eax} \
	__asm{push fs:0} \
	__asm{mov fs:0, esp } \

#define P_CODE_UNINSTALL_SEH  \
	__asm{pop FS:0} \
	__asm{add esp, 4} \
	__asm{pop FS:0} \
	__asm{add esp, 4} 

#define P_CODE_USE_VM \
	bb(0xAA) bb(0xBB) bb(0xCC) bb(0xDD)
	
// below macro's are unused in external
#define INSTALL_SEH(i) \
	__asm{lea eax, i}   \
	__asm{push eax} \
	__asm{push fs:0} \
	__asm{mov fs:0, esp }

#define UNINSTALL_SEH  \
	__asm{pop FS:0} \
	__asm{add esp, 4} \
	__asm{pop FS:0} \
	__asm{add esp, 4} 