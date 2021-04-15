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
	argv = ReactOSCommandLineToArgvW(commandLine, &argc);

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
		
		// set value to NULL
		value = NULL;

		if (*argv[i] == L'-') {
			// pointer to the wchar after '/'
			key = argv[i] + 1;
			
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

				// we want to avoid passing a value with mode flag since we have -t for specifying target PID
				if (value != NULL) {
					error = TRUE;
					printf("[!] Error: -l does not take parameters. Use -t to specify the target PID.\n");
				}
			}			
			else if (*key == SWEEP_MODE) {
				mode = SWEEP_MODE;

				// we want to avoid passing a value with mode flag since we have -t for specifying target PID
				if (value != NULL) {
					error = TRUE;
					printf("[!] Error: -s does not take parameters. Use -t to specify the target PID.\n");
				}

			}				
			else if (*key == UNHOOK_MODE) {
				mode = UNHOOK_MODE;
				// we want to avoid passing a value with mode flag since we have -t for specifying target PID
				if (value != NULL) {
					error = TRUE;
					printf("[!] Error: -u does not take parameters. Use -t to specify the target PID.\n");
				}
			}				
			else if (*key == REHOOK_MODE) {
				mode = REHOOK_MODE;
				// we want to avoid passing a value with mode flag since we have -t for specifying target PID
				if (value != NULL) {
					error = TRUE;
					printf("[!] Error: -r does not take parameters. Use -t to specify the target PID.\n");
				}

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

	// let's invoke a desired function
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
	printf("Usage:\tMineSweeper.exe\t [-c] [-l | -s | -u  | -r] [-t targetPID] [-v]\n\t\t\t[-m moduleNameStringMatch] [-d hookDonorPID]\n");
	printf("Modes available:\n");
	printf("\t-l\tList Mode - List loaded modules by the target process (-t).\n\t\tModule name filter (-m) is available.\n");
	printf("\t-s\tSweep Mode - Sweep target PID (-t) for any user-land hooks.\n\t\tModule name filter (-m) is available.\n");
	printf("\t-u\tUnhook Mode - Sweep and unhook target PID (-t) from any user-land hooks.\n\t\tModule name filter (-m) is available.\n");
	printf("\t-r\tRe-hook Mode - Sweep hook donor PID (-d) for user-land hooks.\n\t\tIf any hooks found - copy them over to our target PID (-t).\n\t\tModule name filter (-m) is available.\n");
	
	printf("Safety modes:\n");
	printf("\t-c\tCautious Mode - Unhook the local process before proceeding with\n\t\tone of the chosen main modes.\n");

	printf("Options:\n");
	printf("\t-t\tTarget PID. Will target the local process if not provided.\n");
	printf("\t-d\tHook donor PID (i.e.: the process that will be used to copy hooks FROM).\n\t\tWill set the local process as the hooks donor if not provided.\n");
	printf("\t-m\tFilter string to be applied to the loaded module canonical path\n\t\t(e.g: \\Device\\HarddiskVolume3\\Windows\\System32\\ntdll.dll).\n\t\tWill target all modules (same as \"-m .dll\") if not provided.\n");
	printf("\t-v\tVerbose flag. Prints modified RVAs and their byte-to-byte comparison for each hooked function.\n");

	printf("Examples:\n");
	printf("MineSweeper.exe: -l \t\tList loaded modules in MineSweeper's own process.\n");
	printf("MineSweeper.exe: -l -t 5476\tList loaded modules in PID 5476.\n");
	printf("MineSweeper.exe: -s\t\tSweep MineSweeper's local process for user-land hooks.\n");
	printf("MineSweeper.exe: -s -v\t\tSame as above but also print modified RVAs for each hooked function.\n");
	printf("MineSweeper.exe: -s -t 5476\tSweep PID 5476 for user-land hooks.\n");
	printf("MineSweeper.exe: -u -t 5476\tUnhook PID 5476 from all user-land hooks.\n");
	printf("MineSweeper.exe: -c -u -t 5476\tUnhook PID 5476 from all user-land hooks. Run in Cautious mode (unhook \n\t\t\t\tMineSweeper's own process before trying to unhook PID 5476).\n");
	printf("MineSweeper.exe: -u -t 5476 -m ntdll.dll\tUnhook PID 5476 from any hooks found in the ntdll.dll module.\n");
	printf("MineSweeper.exe: -r -t 5476 -d 8156\tSweep PID 8156 for user-land hooks and copy over any discovered\n\t\t\t\t\thooks into the matching modules in the PID 5476.\n");
	printf("MineSweeper.exe: -c -r -t 5476 -d 8156\tSame as above but run in Cautious mode (unhook MineSweeper's \n\t\t\t\t\town process before doing anything else).\n");

}

/*
Re-implementing  CommandLineToArgvW in order to avoid importing the Shell32.dll
Source: https://doxygen.reactos.org/da/da5/shell32__main_8c_source.html
*/
LPWSTR* WINAPI ReactOSCommandLineToArgvW(LPCWSTR lpCmdline, int* numargs)
{
	DWORD argc;
	LPWSTR* argv;
	LPCWSTR s;
	LPWSTR d;
	LPWSTR cmdline;
	int qcount, bcount;

	if (!numargs)
	{
		SetLastError(ERROR_INVALID_PARAMETER);
		return NULL;
	}

	if (*lpCmdline == 0)
	{
		/* Return the path to the executable */
		DWORD len, deslen = MAX_PATH, size;

		size = sizeof(LPWSTR) * 2 + deslen * sizeof(WCHAR);
		for (;;)
		{
			if (!(argv = LocalAlloc(LMEM_FIXED, size))) return NULL;
			len = GetModuleFileNameW(0, (LPWSTR)(argv + 2), deslen);
			if (!len)
			{
				LocalFree(argv);
				return NULL;
			}
			if (len < deslen) break;
			deslen *= 2;
			size = sizeof(LPWSTR) * 2 + deslen * sizeof(WCHAR);
			LocalFree(argv);
		}
		argv[0] = (LPWSTR)(argv + 2);
		argv[1] = NULL;
		*numargs = 1;

		return argv;
	}

	/* --- First count the arguments */
	argc = 1;
	s = lpCmdline;
	/* The first argument, the executable path, follows special rules */
	if (*s == '"')
	{
		/* The executable path ends at the next quote, no matter what */
		s++;
		while (*s)
			if (*s++ == '"')
				break;
	}
	else
	{
		/* The executable path ends at the next space, no matter what */
		while (*s && *s != ' ' && *s != '\t')
			s++;
	}
	/* skip to the first argument, if any */
	while (*s == ' ' || *s == '\t')
		s++;
	if (*s)
		argc++;

	/* Analyze the remaining arguments */
	qcount = bcount = 0;
	while (*s)
	{
		if ((*s == ' ' || *s == '\t') && qcount == 0)
		{
			/* skip to the next argument and count it if any */
			while (*s == ' ' || *s == '\t')
				s++;
			if (*s)
				argc++;
			bcount = 0;
		}
		else if (*s == '\\')
		{
			/* '\', count them */
			bcount++;
			s++;
		}
		else if (*s == '"')
		{
			/* '"' */
			if ((bcount & 1) == 0)
				qcount++; /* unescaped '"' */
			s++;
			bcount = 0;
			/* consecutive quotes, see comment in copying code below */
			while (*s == '"')
			{
				qcount++;
				s++;
			}
			qcount = qcount % 3;
			if (qcount == 2)
				qcount = 0;
		}
		else
		{
			/* a regular character */
			bcount = 0;
			s++;
		}
	}

	/* Allocate in a single lump, the string array, and the strings that go
	 * with it. This way the caller can make a single LocalFree() call to free
	 * both, as per MSDN.
	 */
	argv = LocalAlloc(LMEM_FIXED, (argc + 1) * sizeof(LPWSTR) + (wcslen(lpCmdline) + 1) * sizeof(WCHAR));
	if (!argv)
		return NULL;
	cmdline = (LPWSTR)(argv + argc + 1);
	wcscpy(cmdline, lpCmdline);

	/* --- Then split and copy the arguments */
	argv[0] = d = cmdline;
	argc = 1;
	/* The first argument, the executable path, follows special rules */
	if (*d == '"')
	{
		/* The executable path ends at the next quote, no matter what */
		s = d + 1;
		while (*s)
		{
			if (*s == '"')
			{
				s++;
				break;
			}
			*d++ = *s++;
		}
	}
	else
	{
		/* The executable path ends at the next space, no matter what */
		while (*d && *d != ' ' && *d != '\t')
			d++;
		s = d;
		if (*s)
			s++;
	}
	/* close the executable path */
	*d++ = 0;
	/* skip to the first argument and initialize it if any */
	while (*s == ' ' || *s == '\t')
		s++;
	if (!*s)
	{
		/* There are no parameters so we are all done */
		argv[argc] = NULL;
		*numargs = argc;
		return argv;
	}

	/* Split and copy the remaining arguments */
	argv[argc++] = d;
	qcount = bcount = 0;
	while (*s)
	{
		if ((*s == ' ' || *s == '\t') && qcount == 0)
		{
			/* close the argument */
			*d++ = 0;
			bcount = 0;

			/* skip to the next one and initialize it if any */
			do {
				s++;
			} while (*s == ' ' || *s == '\t');
			if (*s)
				argv[argc++] = d;
		}
		else if (*s == '\\')
		{
			*d++ = *s++;
			bcount++;
		}
		else if (*s == '"')
		{
			if ((bcount & 1) == 0)
			{
				/* Preceded by an even number of '\', this is half that
				 * number of '\', plus a quote which we erase.
				 */
				d -= bcount / 2;
				qcount++;
			}
			else
			{
				/* Preceded by an odd number of '\', this is half that
				 * number of '\' followed by a '"'
				 */
				d = d - bcount / 2 - 1;
				*d++ = '"';
			}
			s++;
			bcount = 0;
			/* Now count the number of consecutive quotes. Note that qcount
			 * already takes into account the opening quote if any, as well as
			 * the quote that lead us here.
			 */
			while (*s == '"')
			{
				if (++qcount == 3)
				{
					*d++ = '"';
					qcount = 0;
				}
				s++;
			}
			if (qcount == 2)
				qcount = 0;
		}
		else
		{
			/* a regular character */
			*d++ = *s++;
			bcount = 0;
		}
	}
	*d = '\0';
	argv[argc] = NULL;
	*numargs = argc;

	return argv;
}

/*Debug only: simple function to install some "test hooks" at some random spots in ntdll.dll*/
BOOL installTestHooks(DWORD pid) {
	
	
	HMODULE hModule = GetModuleHandle(L"ntdll.dll");

	HANDLE hTarget = NULL;


	// get PID handle - check whether we are targeting a local or remote process 
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