@echo off

cl.exe /nologo /MT /O2 /Zi /FeLoader.exe Loader.cpp

del /s /q "*.obj"
del /s /q "*.ilk"
del /s /q "*.pdb"