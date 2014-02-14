; THIS STUB WAS CREATED VIA THE FOLLOWING STEPS:
; 1. Compile kmc_stub.cpp and open in OllyDbg
; 2. Rip SetGlobals() and SEH() via Asm2Clipboard (inline asm)
; 		be sure to remove the analysis from the code selection
; 3. Paste ripped code into kmc_stub_template inbetween delta
;    offset code and global variable declaration
; 4. Search and replace global addresses with their varible names
		;	dwOpcodeBackup[0] 				= 1;
		;	dwPrevInstructionAddr 			= 2;
		;	nPrevInstructionLen 			= 3;
		;	nNestingLevel 					= 4;
; 5. Correct references to imagebase
; 		OllyDbg > References > Find references to immediate constant
; 		Patch each reference so they match those shown in olly
; 6. Declare all global varible's at end of file, ensure nested call array is last varible
; 7. Change reference to LDE so LDEX86 is called instead
; 8. Remove DWORD cast when operand size error is given on mov instruction
; 9. Remove invalid syntax of PTR
; 10. Remove SetGlobals() code

[bits 32]
section .text
	global _main

; ====================
; SE handler torn from kmc_stub.cpp
;=====================
SEH:
  call _delta
  _delta:
  pop esi
  sub esi, _delta
  
  ; ripped stub code goes here
  
; ====================
; LDE
;=====================
LDEX86:
 db 0C8h, 008h, 000h, 000h, 060h, 0E9h, 07Bh, 001h
 db 000h, 000h, 058h, 089h, 045h, 0F8h, 033h, 0C0h
 db 089h, 045h, 0FCh, 08Bh, 075h, 008h, 033h, 0FFh
 db 033h, 0D2h, 08Ah, 00Eh, 033h, 0C0h, 08Ah, 0C1h
 db 08Bh, 05Dh, 0F8h, 08Ah, 01Ch, 018h, 080h, 0FBh
 db 020h, 075h, 01Ch, 080h, 0F9h, 066h, 075h, 005h
 db 0BFh, 001h, 000h, 000h, 000h, 080h, 0F9h, 067h
 db 075h, 007h, 0C7h, 045h, 0FCh, 001h, 000h, 000h
 db 000h, 042h, 046h, 08Ah, 00Eh, 0EBh, 0D5h, 033h
 db 0C0h, 080h, 0F9h, 0F6h, 08Ah, 0C1h, 08Bh, 05Dh
 db 0F8h, 08Ah, 004h, 018h, 074h, 005h, 080h, 0F9h
 db 0F7h, 075h, 00Ah, 08Ah, 04Eh, 001h, 0F6h, 0C1h
 db 038h, 074h, 002h, 0B0h, 002h, 085h, 0FFh, 074h
 db 008h, 0A8h, 010h, 074h, 004h, 024h, 0EFh, 00Ch
 db 008h, 08Bh, 04Dh, 0FCh, 085h, 0C9h, 074h, 00Ah
 db 0A8h, 080h, 075h, 006h, 024h, 0EFh, 024h, 0FBh
 db 00Ch, 008h, 0A8h, 080h, 074h, 002h, 024h, 07Fh
 db 03Ch, 040h, 075h, 012h, 042h, 046h, 033h, 0C0h
 db 08Ah, 006h, 08Bh, 05Dh, 0F8h, 081h, 0C3h, 000h
 db 001h, 000h, 000h, 08Ah, 004h, 018h, 042h, 0A8h
 db 002h, 00Fh, 084h, 0B8h, 000h, 000h, 000h, 042h
 db 046h, 08Ah, 00Eh, 08Bh, 0F9h, 081h, 0E7h, 0FFh
 db 000h, 000h, 000h, 08Bh, 0DFh, 0C1h, 0FBh, 006h
 db 084h, 0DBh, 075h, 00Bh, 083h, 0E7h, 007h, 083h
 db 0FFh, 005h, 075h, 003h, 083h, 0C2h, 004h, 033h
 db 0DBh, 08Ah, 0D9h, 08Bh, 0FBh, 0C1h, 0FFh, 006h
 db 083h, 0FFh, 003h, 074h, 058h, 083h, 0E3h, 007h
 db 083h, 0FBh, 004h, 075h, 050h, 042h, 046h, 08Ah
 db 01Eh, 088h, 05Dh, 0FBh, 033h, 0DBh, 08Ah, 0D9h
 db 08Bh, 0F3h, 0C1h, 0FEh, 006h, 04Eh, 075h, 009h
 db 083h, 0E3h, 007h, 083h, 0FBh, 004h, 075h, 001h
 db 042h, 033h, 0DBh, 08Ah, 0D9h, 08Bh, 0F3h, 0C1h
 db 0FEh, 006h, 083h, 0FEh, 002h, 075h, 00Bh, 083h
 db 0E3h, 007h, 083h, 0FBh, 004h, 075h, 003h, 083h
 db 0C2h, 004h, 033h, 0DBh, 08Ah, 0D9h, 0C1h, 0FBh
 db 006h, 084h, 0DBh, 075h, 010h, 033h, 0DBh, 08Ah
 db 05Dh, 0FBh, 083h, 0E3h, 007h, 083h, 0FBh, 005h
 db 075h, 003h, 083h, 0C2h, 004h, 080h, 0F9h, 040h
 db 072h, 012h, 080h, 0F9h, 07Fh, 077h, 00Dh, 033h
 db 0DBh, 08Ah, 0D9h, 083h, 0E3h, 007h, 083h, 0FBh
 db 004h, 074h, 001h, 042h, 080h, 0F9h, 080h, 072h
 db 016h, 080h, 0F9h, 0BFh, 077h, 011h, 081h, 0E1h
 db 0FFh, 000h, 000h, 000h, 083h, 0E1h, 007h, 083h
 db 0F9h, 004h, 074h, 003h, 083h, 0C2h, 004h, 08Bh
 db 0C8h, 0F6h, 0C1h, 010h, 074h, 003h, 083h, 0C2h
 db 004h, 0F6h, 0C1h, 004h, 074h, 001h, 042h, 0F6h
 db 0C1h, 008h, 074h, 003h, 083h, 0C2h, 002h, 084h
 db 0C0h, 075h, 001h, 042h, 089h, 054h, 024h, 01Ch
 db 061h, 0C9h, 0C2h, 004h, 000h, 0E8h, 080h, 0FEh
 db 0FFh, 0FFh, 002h, 002h, 002h, 002h, 004h, 010h
 db 001h, 001h, 002h, 002h, 002h, 002h, 004h, 010h
 db 001h, 040h, 002h, 002h, 002h, 002h, 004h, 010h
 db 001h, 001h, 002h, 002h, 002h, 002h, 004h, 010h
 db 001h, 001h, 002h, 002h, 002h, 002h, 004h, 010h
 db 020h, 001h, 002h, 002h, 002h, 002h, 004h, 010h
 db 020h, 001h, 002h, 002h, 002h, 002h, 004h, 010h
 db 020h, 001h, 002h, 002h, 002h, 002h, 004h, 010h
 db 020h, 001h, 001h, 001h, 001h, 001h, 001h, 001h
 db 001h, 001h, 001h, 001h, 001h, 001h, 001h, 001h
 db 001h, 001h, 001h, 001h, 001h, 001h, 001h, 001h
 db 001h, 001h, 001h, 001h, 001h, 001h, 001h, 001h
 db 001h, 001h, 001h, 001h, 002h, 002h, 020h, 020h
 db 020h, 020h, 010h, 012h, 004h, 006h, 001h, 001h
 db 001h, 001h, 084h, 084h, 084h, 084h, 084h, 084h
 db 084h, 084h, 084h, 084h, 084h, 084h, 084h, 084h
 db 084h, 084h, 006h, 012h, 006h, 006h, 002h, 002h
 db 002h, 002h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 001h, 001h, 001h, 001h, 001h, 001h
 db 001h, 001h, 001h, 001h, 018h, 001h, 001h, 001h
 db 001h, 001h, 010h, 010h, 010h, 010h, 001h, 001h
 db 001h, 001h, 004h, 010h, 001h, 001h, 001h, 001h
 db 001h, 001h, 004h, 004h, 004h, 004h, 004h, 004h
 db 004h, 004h, 010h, 010h, 010h, 010h, 010h, 010h
 db 010h, 010h, 006h, 006h, 008h, 001h, 002h, 002h
 db 006h, 012h, 00Ch, 001h, 008h, 001h, 001h, 004h
 db 001h, 001h, 002h, 002h, 002h, 002h, 004h, 004h
 db 001h, 001h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 084h, 084h, 084h, 084h, 004h, 004h
 db 004h, 004h, 090h, 090h, 018h, 004h, 001h, 001h
 db 001h, 001h, 020h, 001h, 020h, 020h, 001h, 001h
 db 006h, 012h, 001h, 001h, 001h, 001h, 001h, 001h
 db 002h, 002h, 002h, 002h, 002h, 002h, 000h, 000h
 db 001h, 000h, 001h, 001h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 002h, 002h, 002h, 002h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 001h, 001h, 001h, 001h, 001h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 010h, 010h, 010h, 010h, 010h, 010h
 db 010h, 010h, 010h, 010h, 010h, 010h, 010h, 010h
 db 010h, 010h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 001h, 001h, 001h, 002h, 006h, 002h
 db 000h, 000h, 001h, 001h, 001h, 002h, 006h, 002h
 db 000h, 002h, 002h, 002h, 002h, 002h, 002h, 002h
 db 002h, 002h, 000h, 000h, 006h, 002h, 002h, 002h
 db 002h, 002h, 002h, 002h, 000h, 000h, 000h, 000h
 db 000h, 000h, 001h, 001h, 001h, 001h, 001h, 001h
 db 001h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
 db 000h, 000h
 
; globals	
	db(0x00)
	nPrevInstructionLen:			dd(0x00000000) ; -
	db(0x00)
	dwPrevInstructionAddr:			dd(0x00000000) ; -
	db(0x00)
	nNestingLevel:					dd(0x00000000) ; -
	db(0x00)
	dwOpcodeBackup:  				
		dd(0x00000000) ; -
		dd(0x00000000)
		dd(0x00000000)
		dd(0x00000000)
		dd(0x00000000)
		dd(0x00000000)