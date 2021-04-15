#pragma once
#include <Windows.h>
#include "MineSweeperCore.h"
#include <stdlib.h> // for command line parsing

BOOL installTestHooks(DWORD);
BOOL processCommandLineParams(int argc, wchar_t* argv[]);
void printUsageInfo();
extern BOOL beVerbose;
LPWSTR* WINAPI ReactOSCommandLineToArgvW(LPCWSTR lpCmdline, int* numargs);