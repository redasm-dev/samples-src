# Building Masm0
 
## 1. Install MASM32 SDK
 
Download [MASM32 SDK](https://www.masm32.com/download.htm) (pick any mirror), run the installer, install to the default path `C:\masm32`.

## 2. Build
 
```cmd
set PATH=C:\masm32\bin;%PATH%
cd C:\path\to\Masm0
ml /c /coff /I"C:\masm32\include" Masm0.Asm
rc /I"C:\masm32\include" Masm0.Rc
link /SUBSYSTEM:WINDOWS Masm0.obj Masm0.res /LIBPATH:"C:\masm32\lib" /OUT:Masm0.exe
