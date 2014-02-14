@cmd /C "C:\Program Files\Microsoft Visual Studio\VC98\Bin\VCVARS32.BAT" & cl /Od /MD /nologo KMCTarget.cpp /link /nologo gmp.lib kernel32.lib user32.lib gdi32.lib winspool.lib comctl32.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib winmm.lib wininet.lib ws2_32.lib vfw32.lib & del KMCTarget.obj
KMCVirtualizer.exe KMCTarget.exe
KMCTarget.exe
@pause