@ECHO OFF

rc resources.rc
cvtres /MACHINE:x64 /OUT:resources.o resources.res
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG bread.cpp /link /OUT:bread.exe /SUBSYSTEM:CONSOLE /MACHINE:x64 resources.o 