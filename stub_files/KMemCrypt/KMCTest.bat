@cmd /C "C:\Program Files\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" & cl /Od /MD /nologo kmc_encrypt_mem.cpp /link /nologo gmp.lib kernel32.lib user32.lib gdi32.lib winspool.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib wininet.lib ws2_32.lib vfw32.lib & del kmc_encrypt_mem.obj
@cmd /C "C:\Program Files\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" & cl /Od /MD /nologo kmc_stub.cpp /link /nologo gmp.lib kernel32.lib user32.lib gdi32.lib winspool.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib wininet.lib ws2_32.lib vfw32.lib & del kmc_stub.obj
kmc_encrypt_mem.exe kmc_stub.exe
kmc_stub.exe
@pause