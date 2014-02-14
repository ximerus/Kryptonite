REM KCrypt V2.1 cryter interface
@SET /P targetfile="Enter target file's name: "
@echo --- Building stubs ---
..\stub_files\nasm\nasm.exe ..\stub_files\KBinCrypt\kbc_stub.asm
..\stub_files\nasm\nasm.exe ..\stub_files\KMemCrypt\kmc_stub.asm
@echo --- Backing up target file ---
copy /Y %targetfile% %targetfile%.bak
@echo --- Loading Kryptonite interface ---
@..\KInterface\KInterface.exe %targetfile% KOrUPt
@SET /P Exec="Execute protected file? [y/n]: "
@IF /i %Exec% == y GOTO :ExecFile
@GOTO :SkipExec
:ExecFile
@echo --- Executing file ---
@%targetfile%
:End
:SkipExec
@SET /P ShouldRestore="Restore target file? [y/n]: "
@IF /i %ShouldRestore% == y GOTO :RestoreTarget
@echo --- Target not restored ---
@pause
@goto :eof
:RestoreTarget
@echo off
@copy /Y %targetfile%.bak %targetfile%
@echo on
@echo --- Target restored ---
@pause
:END