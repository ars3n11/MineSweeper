#include "MineSweeperCore.h"
#include "MineSweeper.h"

// we avoid using main() / wmain() to avoid linking to Visual Studio provided C run-time (CRT) (invokes mainCRTStartup function first).
// idea taken from http://www.exploit-monday.com/2013/08/writing-optimized-windows-shellcode-in-c.html
// Note: we do still link to CRT since we need it for IO operations and string comparison but we use Microsoft's system dll (msvcrt.dll) instead which comes with every Windows NT build and doesn't have Visual Studio CRT overhead
int wmain_custom()
{
	LPWSTR commandLine;
	int argc;
	wchar_t** argv;
	// since we don't rely on Visual Studio CRT to pass us the command line parameters, we have to get those ourselves
	commandLine = GetCommandLineW();
	// parse command line arguments
	argv = CommandLineToArgvW(commandLine, &argc);

	if (!processCommandLineParams(argc, argv)) {
		return 1;
	}

	return 0;
}

/*
Basic command line parameters parsing function. 
*/
BOOL processCommandLineParams(int argc, wchar_t* argv[]) {
	wchar_t mode = NULL, * moduleName = NULL;
	DWORD pid = NULL, pidHookDonor = NULL;
	BOOL error = FALSE, cautiousMode = FALSE;
	
	wchar_t * key, * value;

	// code sample from here https://stackoverflow.com/questions/12689142/win32-api-command-line-arguments-parsing
	for (int i = 1; i < argc; i++) {
		
		if (*argv[i] == L'-') {
			// pointer to the wchar after '/'
			key = argv[i] + 1;
			value = key + 1;
			
			// make sure there is i+1 before attempting to read it 
			if (i + 1 < argc) {
				if (*argv[i + 1] != L'-') {
					i++;
					value = argv[i];
				}
				else {
					value == NULL;
				}
			}
			else {
				value == NULL;
			}
			
			if (*key == L'h' || *key == L'H') {
				printUsageInfo();
				return TRUE;
			}
			else if (*key == LIST_MODE) {
				mode = LIST_MODE;
			}			
			else if (*key == SWEEP_MODE) {
				mode = SWEEP_MODE;
			}				
			else if (*key == UNHOOK_MODE) {
				mode = UNHOOK_MODE;
			}				
			else if (*key == REHOOK_MODE) {
				mode = REHOOK_MODE;
			}				
			// parse the target parameter
			else if (*key == L't') {
				if (value != NULL){
					pid = wcstoul(value, NULL, 10);
					if (pid == NULL) {
						printf("[!] Invalid input: -t flag parameter must be an integer!.\n");
						error = TRUE;
					}
				}				
				else {
					printf("[!] Error: -t flag is missing a value.\n");
					error = TRUE;
				}

			}
			// parse the hook donor param
			else if (*key == L'd') {
				if (value != NULL) {
					pidHookDonor = wcstoul(value, NULL, 10);
					if (pidHookDonor == NULL) {
						printf("[!] Invalid input: -d flag parameter must be an integer!.\n");
						error = TRUE;
					}
				}
				else {
					printf("[!] Error: -d flag is missing a value.\n");
					error = TRUE;
				}

			}
			// parse target module
			else if (*key == L'm') {
				if (value != NULL) {
					moduleName = value;
				}
				else {
					printf("[!] Error: -m requires a module name!\n");
					error = TRUE;
				}
			}
			// if cautious mode 
			else if (*key == CAUTIOUS_MODE){
				cautiousMode = TRUE;
			}
			// verbose mode
			else if (*key == L'v') {
				beVerbose = TRUE;
			}				
			else {
				printf("[!] Invalid input: %ls\n", argv[i]);
			}
		}
		else {
			printf("[!] Invalid input: %ls\n", argv[i]);
			error = TRUE;
		}
	}

	if (mode == NULL && error == FALSE) {
		printf("[!] Mode not selected.\n");
		error = TRUE;
		
	}

	if (error) {
		printf("[!] Use -h for help.\n");
		return FALSE;
	}

	// if cautious mode is on, let's unhook our local process
	if (cautiousMode) {
		printf("[*] Cautious mode is on: unhooking the local process first");
		// if we failed to unhook our local process - stop
		if (!unhookProcessModules(NULL, NULL)) {
			printf("[!] Cautious mode: failed to unhook the local process. Abort the mission.\n");
			return FALSE;
		}
	}

	// let's invoke a desired funtion
	switch (mode){
		case LIST_MODE:
			
			printf("[*] Mode: List Mode\n");
			
			if (pid != NULL)
				printf("\tTarget PID: %d\n", pid);
			else
				printf("\tTarget PID: local\n");

			if (moduleName != NULL)
				printf("\tTarget module: %ls\n", moduleName);
			else
				printf("\tTarget module: all\n");

			listProcessModules(pid, moduleName);

			break;

		case SWEEP_MODE:
			
			printf("[*] Mode: Sweep Mode (hook enum)\n");

			if (pid != NULL)
				printf("\tTarget PID: %d\n", pid);
			else
				printf("\tTarget PID: local\n");

			if (moduleName != NULL)
				printf("\tTarget module: %ls\n", moduleName);
			else
				printf("\tTarget module: all\n");

			sweepProcessModules(pid, moduleName);

			break;

		case UNHOOK_MODE:

			printf("[*] Mode: Unhook Mode\n");

			if (pid != NULL)
				printf("\tTarget PID: %d\n", pid);
			else
				printf("\tTarget PID: local\n");

			if (moduleName != NULL)
				printf("\tTarget module: %ls\n", moduleName);
			else
				printf("\tTarget module: all\n");

			unhookProcessModules(pid, moduleName);

			break;

		case REHOOK_MODE:

			printf("[*] Mode: Re-hook Mode\n");

			// pid and hook donor pid are not allowed to match
			if (pid == pidHookDonor) {
				printf("[!] The target PID (/t) and the hook donor PID (/d) cannot be the same!\n[!] You alright, bro? maybe it's time for a break..\n");
				return FALSE;
			}

			if (pid != NULL)
				printf("\tTarget PID: %d\n", pid);
			else
				printf("\tTarget PID: local\n");

			if (pidHookDonor != NULL)
				printf("\tHook donor PID: %d\n", pidHookDonor);
			else
				printf("\tHook donor: local\n");

			if (moduleName != NULL)
				printf("\tTarget module: %ls\n", moduleName);
			else
				printf("\tTarget module: all\n");

			rehookProcessModules(pid, moduleName, pidHookDonor);

			break;

		default:
			break;
	}

	return TRUE;
}

/*
Print out the usage info
*/
void printUsageInfo() {
	printf("MineSweeper by @ars3n11\n");
	printf("Usage:\tMineSweeper.exe\t [-c] [-l | -s | -u  | -r] [-t targetPID]\n\t\t\t[-m moduleNameStringMatch] [-d hookDonorPID]\n");
	printf("Modes available:\n");
	printf("\t-l\tList Mode - List loaded modules by the target PID (-t).\n\t\tModule name filter (-m) is available.\n");
	printf("\t-s\tSweep Mode - Sweep target PID (-t) for any user-land hooks.\n\t\tModule name filter (-m) is available.\n");
	printf("\t-u\tUnhook Mode - Sweep and unhook target PID (-t) from any user-land hooks.\n\t\tModule name filter (-m) is available.\n");
	printf("\t-r\tRe-hook Mode - Sweep hook donor PID (-d) for user-land hooks.\n\t\tIf any hooks found - copy them over to our target PID (-t).\n\t\tModule name filter (-m) is available.\n");
	
	printf("Safety modes:\n");
	printf("\t-c\tCautious Mode - Unhook the local process before proceeding with\n\t\tone of the choosen main modes.\n");

	printf("Options:\n");
	printf("\t-t 1234\tTarget PID. If not provided - target local process.\n");
	printf("\t-d 1234\tHook donor PID (i.e.: the process that will be used to copy hooks FROM).\n\t\tIf not provided - set local process as the hook donor.\n");
	printf("\t-m module.dll\tFilter string to be applied to the loaded module canonical path\n\t\t(e.g: \\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll).\n\t\tIf not provided - target all modules (same as \"-m .dll\".\n");
	printf("\t-v\tVerbose flag. Prints modified RVAs for each hooked function.\n");

	printf("Examples:\n");
	printf("MineSweeper.exe: -l -t 5476\tList loaded modules in PID 5476.\n");
	printf("MineSweeper.exe: -s\t\tSweep local process for user-land hooks.\n");
	printf("MineSweeper.exe: -s -v\t\tSame as above but also print but also print modified RVAs for each hooked function.\n");
	printf("MineSweeper.exe: -u -t 5476\tUnhook PID 5476 from all user-land hooks.\n");
	printf("MineSweeper.exe: -c -u -t 5476\tUnhook PID 5476 from all user-land hooks. Run in Cautious mode.\n");
	printf("MineSweeper.exe: -u -t 5476 -m ntdll.dll Unhook PID 5476 from any hooks found in tne ntdll.dll module.\n");
	printf("MineSweeper.exe: -r -t 5476 -d 8156\tSweep PID 8156 for user-land hooks and copy over any discovered\n\t\t\t\t\thooks into the matching modules in the PID 5476.\n");
	printf("MineSweeper.exe: -c -r -t 5476 -d 8156\tSame as above but run in Cautious mode.\n");

}

/*Debug only: simple function to install some "test hooks" at some random spots in ntdll.dll*/
BOOL installTestHooks(DWORD pid) {
	
	
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	HANDLE hTarget = NULL;


	// get PID handle - check wether we are targetting a local or remote process 
	if (pid == NULL) {
		hTarget = GetCurrentProcess();	}
	else {
		hTarget = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	}
	
	PIMAGE_SECTION_HEADER textSectionHeader = getTextSection(hModule);

	DWORD_PTR textSection = textSectionHeader->VirtualAddress + (DWORD_PTR)hModule;

	DWORD oldProtect = 0;

	DWORD newProtect = PAGE_EXECUTE_READWRITE;

	if (!VirtualProtectEx(hTarget, textSection, 1024 * 40, newProtect, &oldProtect)) {
#if _DEBUG
		printf("[!] VirtualProtectEx failed!%d\n");
#endif
		return FALSE;
	}
	

	BYTE buffer[10] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };

	DWORD_PTR memoryChangeStartAddress = textSection + 400;

	if (!WriteProcessMemory(hTarget, memoryChangeStartAddress, buffer, 10, NULL)) {
		// if we failed to write into process memory - pull back
#if _DEBUG
		printf("[!] WriteProcessMemory failed - %d\n", GetLastError());
#endif
	}

	memoryChangeStartAddress = memoryChangeStartAddress + 2000;

	if (!WriteProcessMemory(hTarget, memoryChangeStartAddress, buffer, 2, NULL)) {
		// if we failed to write into process memory - pull back
#if _DEBUG
		printf("[!] WriteProcessMemory failed - %d\n", GetLastError());
#endif
	}

	memoryChangeStartAddress = memoryChangeStartAddress + 4;


	if (!WriteProcessMemory(hTarget, memoryChangeStartAddress, buffer, 3, NULL)) {
		// if we failed to write into process memory - pull back
#if _DEBUG
		printf("[!] WriteProcessMemory failed - %d\n", GetLastError());
#endif
	}


	if (!VirtualProtectEx(hTarget, textSection, 1024, oldProtect, &newProtect)) {
#if _DEBUG
		printf("[!] VirtualProtectEx failed restoring permissions after unhook/re-hook!%d\n");
#endif
		return FALSE;
	}

	printf("Test hooking succeeded\n");

	return TRUE;

}