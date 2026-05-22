
@echo off

set OUTPUTNAME=program

ml64 /nologo /c /Zi /Cp solve_funcs.asm

cl /nologo /O2 /Zi /utf-8 /EHa /Fe%OUTPUTNAME%.exe EvadeEDR.cpp solve_funcs.obj

del /s /q "*.obj"
del /s /q "*.ilk"
del /s /q "*.pdb"