#pragma once
#include <Windows.h>
#include "MineSweeperCore.h"
#include <stdlib.h> // for command line parsing
#pragma comment(lib, "Onecore.lib") // for QueryVirtualMemoryInformation

BOOL installTestHooks(DWORD);
BOOL processCommandLineParams(int argc, wchar_t* argv[]);
void printUsageInfo();
extern BOOL beVerbose;