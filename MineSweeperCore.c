#include "MineSweeperCore.h"
BOOL beVerbose = FALSE; // verbose flag

// copies over remote process module to a local process buffer using ReadProcessMemory API
DWORD_PTR readRemoteModule(HMODULE hModule, HANDLE hProcess) {
	
	MEMORY_BASIC_INFORMATION memoryBasicInformation = { 0 };
	
	SIZE_T dllAllocationSize = 0;
	
	DWORD_PTR base = (DWORD_PTR)hModule;

	DWORD lastError = 0;

	LPVOID remoteModuleBuffer = NULL;

	// Get memory region info to find out the region size for our target module 
	// note: for x86 project sizeof(memInfo) returns 0x14 but the QueryVirtualMemoryInformation() function will fail it it's not 0x20 (which is the value that x64 binary would would get)

	// Create required struct for the QueryVirtualMemoryInformation func
	//WIN32_MEMORY_REGION_INFORMATION memInfo = { 0 };

//	if (!QueryVirtualMemoryInformation(hProcess, hModule, MemoryRegionInfo, &memInfo, sizeof(memInfo), &writtenSize)) {
//		// note: WinAPI bug alert:  for x86 project sizeof(memInfo) returns 0x14 but the QueryVirtualMemoryInformation() function will fail if meminfo size is anything but 0x20 (which is the value that x64 project would have)
//		if (!QueryVirtualMemoryInformation(hProcess, hModule, MemoryRegionInfo, &memInfo, 0x20, &writtenSize)) {
//
//#if _DEBUG
//			printf("Failed to QueryVirtualMemoryInformation. Last error: %d\n", GetLastError());
//#endif		
//			return NULL;
//		}
//	}
	
	// Loop through entire dll memory allocation section by section until we find out it's entire size
	while (TRUE) {
		if (VirtualQueryEx(hProcess, base, &memoryBasicInformation, sizeof(memoryBasicInformation))) {
			// if allocation base matches with our target module handle (which acts as module base address as well)
			if (memoryBasicInformation.AllocationBase == (PVOID)hModule) {
				dllAllocationSize += memoryBasicInformation.RegionSize;
				base += memoryBasicInformation.RegionSize;
			}
			else {
				break;
			}
			
		}
		else {
#if _DEBUG
			printf("[!] Failed to VirtualQueryEx remote process memory! Last error: %d\n", lastError);
#endif
			return NULL;

		}
	}
	

	// now that we know the size of the target module, let's allocate our buffer
	remoteModuleBuffer = malloc(dllAllocationSize);
	//remoteModuleBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dllAllocationSize);

	// now copy over the target module from the remote process
	if (!ReadProcessMemory(hProcess, hModule, remoteModuleBuffer, dllAllocationSize, NULL)) {
		lastError = GetLastError();
		free(remoteModuleBuffer);
		// in case ReadProcessMemory received error 299 (ERROR_PARTIAL_COPY) - return 1 - initializeMineSweeperModuleInfo will know what to do
		if (lastError == 299) {
			return 1;
		}
		else {
#if _DEBUG
			printf("[!] Failed to read remote process memory! Last error: %d\n", lastError);
#endif
			return NULL;
		}

	}



	return remoteModuleBuffer;
}

// retrieves target module file path
wchar_t* getModuleFilePath(HMODULE hModule, HANDLE hProcess) {
	PWSTR tempFileName[filePathLength] = { 0 }; // create a temporary PWSTR to be used with file name retrieval
	DWORD fileNameLength; // to be used with file name retrievel
	wchar_t* filePath = NULL;

	// if process handle is NULL, let's get a handle to our local process
	if (!hProcess)
		hProcess = GetCurrentProcess();

	// first, let's see how long  the file name is:
	//fileNameLength = GetModuleFileNameExW(hProcess, hModule, tempFileName, filePathLength);
	// Note: we are using GetMappedFileNameW as per thread here in order to avoid wow64 file system redirector for 32-bit processes as per https://stackoverflow.com/questions/48178586/how-to-disable-wow64-file-system-redirection-for-getmodulefilenameex
	fileNameLength = GetMappedFileNameW(hProcess, hModule, tempFileName, filePathLength);

	// if there was an error retrieving the module's file name
	if (fileNameLength == 0 || GetLastError() != 0) {
#if _DEBUG
		printf("[!] Error retrieving module file name. Module handle: %#X\n", hModule);
#endif
		return NULL;
	}

	// add 1 to account for the terminating null byte 
	fileNameLength++;

	// now let's allocate enough space to hold our file name 
	filePath = (wchar_t*)malloc(sizeof(wchar_t) * fileNameLength);


	// now, let's finally retrieve the file name
	//if (GetModuleFileNameExW(hProcess, hModule, filePath, filePathLength) == 0 || GetLastError() != 0) {
	if (GetMappedFileNameW(hProcess, hModule, filePath, filePathLength) == 0 || GetLastError() != 0) {
#if _DEBUG
		printf("[!] Error retrieving module file name on the second atttempt. Module handle: %#X\n", hModule);
#endif
		free(filePath);
		return NULL;
	}
	
	return filePath;

}

/*
A function to check wether more than 1% of the .text section has been detected to be overwritten. Returns TRUE if more than 1% of the .text section have been modified.
1% was picked based on real-world AV observations.
This function was created to accommodate for an edge case scenario where large parts of .text section of the module happens to be overwritten. While the reason for this phenomenon is uknown it did happened a few times during my testing.
*/
BOOL isTextSectionOverwritten(mineSweeperModuleInfo* targetModule) {

	PIMAGE_SECTION_HEADER inMemoryTextSectionHeader = NULL;

	inMemoryTextSectionHeader = getTextSection(targetModule->moduleBase);

	DWORD sectionSize = inMemoryTextSectionHeader->Misc.VirtualSize;
	// if the number of modified bytes in the .text section is greater than 1% of the entire .text section, consider the section to be overwritten
	if (targetModule->modifiedRVAsLength > sectionSize / 100 ) {
		return TRUE;
	}

	return FALSE;

}

// Initialize mineSweeperModuleInfo struct. If processHandle is NULL, then the function assumes that the target module is in the local process. Otherwise, it will treat the target module as a remote process module.
mineSweeperModuleInfo* initializeMineSweeperModuleInfo(HMODULE hModule, HANDLE hProcess) {
	mineSweeperModuleInfo* targetModule;
	
	// allocate memory for our mineSweeperModuleInfo struct
	targetModule = (mineSweeperModuleInfo*)malloc(sizeof(mineSweeperModuleInfo));

	// zero the contents of the struct
	SecureZeroMemory(targetModule, sizeof(mineSweeperModuleInfo));

	targetModule->hModule = hModule;

	targetModule->hProcess = hProcess;

	// get module filePath
	targetModule->filePath = getModuleFilePath(hModule, hProcess);

	if (targetModule->filePath == NULL) {
		free(targetModule);
		return NULL;
	}

	// extracting the module name out of the module path. the arithmetrics below is in order to avoid the last backslash. We add 2 instead of 1 because this is a wide string.
	targetModule->moduleName = (DWORD_PTR)wcsrchr(targetModule->filePath, L'\\') + 2;

	// check whether we are targeting a local or remote process module
	if (hProcess != GetCurrentProcess()) {
		// if remote process - copy over the remote process module
		targetModule->moduleBase = readRemoteModule(hModule, hProcess);
		
		// in case we failed to read the remote process module - pull back
		if (targetModule->moduleBase == 1 || targetModule->moduleBase == NULL) {
			
			// in case ReadProcessMemory received error 299 (ERROR_PARTIAL_COPY) 
			if (targetModule->moduleBase == 1) {
				printf("[!] %#X (%ls): the module is commited into memory only partially, we have to skip it.\n", targetModule->hModule, targetModule->moduleName);
			}
			
			free(targetModule);
			return NULL;
		}
	}
	else {
		// if we are targeting a local process module - set module base to our hModule value
		targetModule->moduleBase = hModule;
	}


	// check for MZ signature at the start of the module, mind little endianess
	WORD* mz = targetModule->moduleBase;
	if (*mz != 0x5A4D){
#if _DEBUG
		printf("[!] MZ signature is missing!\n");
#endif
		if (hProcess != GetCurrentProcess()) {
			free(targetModule->moduleBase);
		}
		free(targetModule);
		return NULL;
	}
	

	// get Export Directory Table - note we path module base and not hModule in case we are working with a remote process module
	targetModule->edt = getExportDirectoryTable(targetModule->moduleBase);

	if (targetModule->edt == NULL){
		if (hProcess != GetCurrentProcess()) {
			free(targetModule->moduleBase);
		}
		free(targetModule);
		return NULL;
	}
	
	targetModule->eat = targetModule->edt->AddressOfFunctions + targetModule->moduleBase;

	targetModule->eot = targetModule->edt->AddressOfNameOrdinals + targetModule->moduleBase;

	targetModule->npt = targetModule->edt->AddressOfNames + targetModule->moduleBase;

	


	return targetModule;
}

/*
Builds a hooked functions list using a pointer to a valid mineSweeperModuleInfo struct.
Returns the length of the list or 0 if no list was created.
*/
DWORD buildHookedFunctionsArray(mineSweeperModuleInfo* targetModule) {
	DWORD uniqueFuncCounter = 0;
	int prevEATOrdinal = -1;
	
	// convenience variables
	DWORD RVAsCount = targetModule->modifiedRVAsLength; 
	DWORD_PTR moduleBase = targetModule->moduleBase;
	
	// if no modifired RVAs are present there is nothing to work on
	if (targetModule->modifiedRVAsLength < 1)
		return uniqueFuncCounter;

	// temp array to hold RVA to EAT mapping
	PWORD tempRVAtoEatMapping = malloc(sizeof(WORD) * RVAsCount);

	// map modified RVAs to respective EAT function ordinals
	for (DWORD i = 0; i < RVAsCount; i++) {
		tempRVAtoEatMapping[i] = findClosestEAT_RVA(moduleBase + targetModule->modifiedRVAs[i], moduleBase, targetModule->eat, targetModule->edt->NumberOfFunctions);
	}

	// calculate unique hooked functions
	for (DWORD i = 0; i < RVAsCount; i++) {
		if (tempRVAtoEatMapping[i] != prevEATOrdinal) {
			uniqueFuncCounter++;
			prevEATOrdinal = tempRVAtoEatMapping[i];
		}	
	}

	// if for some reason we didn't find any hooked functions - return
	if (uniqueFuncCounter == 0) {
		free(tempRVAtoEatMapping);
		return uniqueFuncCounter;
	}
		

	// allocate memory for our hookedFunctions array
	targetModule->hookedFunctions = malloc(sizeof(hookedFunction) * uniqueFuncCounter);

	// now let's populate our hookedFunctions array
	for (DWORD i = 0, currentRVAArrayIndex = 0; i < uniqueFuncCounter; i++) {
		// asign eat ordianl value to our hooked function 		
		targetModule->hookedFunctions[i].eatOrdinal = tempRVAtoEatMapping[currentRVAArrayIndex];

		// increase tempCounter by one since we just assigned the current EAT value
		currentRVAArrayIndex++;

		// temporary variable to keep track of how many modified RVAs are there for each hookedFunctions memenber. We start with since there is at least 1
		DWORD countRVAs = 1;
		// let's calculate how many modified RVAs belong to our current hookedFunctions member 
		for (; currentRVAArrayIndex < RVAsCount; currentRVAArrayIndex++) {
			//if our current hooked function EAT matches the tempRVAtoEatMapping[tempCounter] - that RVA belongs to the same function, so increase the RVAs counter, otherwise, we need to get out
			if (targetModule->hookedFunctions[i].eatOrdinal == tempRVAtoEatMapping[currentRVAArrayIndex])
				countRVAs++;
			else
				break;
		}
		// we now know the modifiedRVAsIndexesLength value
		targetModule->hookedFunctions[i].modifiedRVAsIndexesCount = countRVAs;

		// it's time to allocate memory for our modifiedRVAsIndexes array
		targetModule->hookedFunctions[i].modifiedRVAsIndexes = malloc(sizeof(WORD) * countRVAs);

		// let's populate modifiedRVAsIndexes values
		for (DWORD j = 0, tempRVAIndex = currentRVAArrayIndex - countRVAs; tempRVAIndex < currentRVAArrayIndex; tempRVAIndex++, j++) {
			targetModule->hookedFunctions[i].modifiedRVAsIndexes[j] = tempRVAIndex;
		}

		// let's translate our function EAT index into EOT / NPT index
		targetModule->hookedFunctions[i].eotOrdinal = EATIndexToEOTIndex(targetModule->hookedFunctions[i].eatOrdinal, targetModule->eot, targetModule->edt->NumberOfNames);

		// checking just in case EATIndexToEOTIndex didn't find appropriate EOT index (which shouldn't normally happen)
		if (targetModule->hookedFunctions[i].eotOrdinal != -1)
			// get the function name
			targetModule->hookedFunctions[i].functionName = EOTIndexToFuncNameMineSweeper(targetModule, targetModule->hookedFunctions[i].eotOrdinal);

	}

	// now set the hookedFunctionsLength value
	targetModule->hookedFunctionsLength = uniqueFuncCounter;

	free(tempRVAtoEatMapping);

	return uniqueFuncCounter;
}

void printHookedFunctions(mineSweeperModuleInfo* targetModule) {
	
	DWORD ordinalBase;

	// check if there are any modified RVAs in the module
	if (targetModule->modifiedRVAsLength < 1) {
		return;
	}
		

	// check if there are any hooked functions detected. If not, try build a new hookedFunctionsList
	if (targetModule->hookedFunctionsLength < 1)
		buildHookedFunctionsArray(targetModule);

	// if still no hooked functions - return
	if (targetModule->hookedFunctionsLength < 1)
		return;

	ordinalBase = targetModule->edt->Base;

	printf("\tHooked functions detected: %d\n\n", targetModule->hookedFunctionsLength);

	for (DWORD i = 0; i < targetModule->hookedFunctionsLength; i++) {
		printf("\t%d) %d %s\n", i + 1, targetModule->hookedFunctions[i].eatOrdinal + ordinalBase, targetModule->hookedFunctions[i].functionName);
		
		if (beVerbose) {
			// if one function has over 30 modified RVA, let's skip it - some weird shit is happening (observed on some obscured .dll like windows.storage.dll)
			if (targetModule->hookedFunctions[i].modifiedRVAsIndexesCount > 30) {
				printf("\t\t%d modified RVAs (too many to print!)\n", targetModule->hookedFunctions[i].modifiedRVAsIndexesCount);
				continue;
			}

			for (WORD j = 0; j < targetModule->hookedFunctions[i].modifiedRVAsIndexesCount; j++) {
				WORD index = targetModule->hookedFunctions[i].modifiedRVAsIndexes[j];
				// note 0x%2X to append "0x" to zero
				printf("\t\tRVA: %#X - 0x%02X -> 0x%02X\n", targetModule->modifiedRVAs[index], targetModule->unhookedRVAValues[index], targetModule->hookedRVAValues[index]);
			}
			printf("\n");
		}
		
	}

}




// Check specified module for user-land hooks by comparing its in-memory copy with the one on disk
// Returns FALSE in case of any errors
BOOL sweepModule(mineSweeperModuleInfo* targetModule) {
	PIMAGE_SECTION_HEADER inMemoryTextSectionHeader = NULL, onDiskTextSectionHeader = NULL; // section header variables
	DWORD_PTR inMemoryTextSection, onDiskTextSection;
	int memcmpResult = 0;
	DWORD modifiedRVAsCount = 0;

	if (targetModule == NULL)
		return FALSE;

	// linked list variables 
	modifiedRVAListNode* head = NULL;
	modifiedRVAListNode* prev = NULL;
	modifiedRVAListNode* current;

	// map module from disk
	if (mapFileFromDisk(targetModule) == FALSE) {
#if _DEBUG
		printf("[!] Failed to map the file from disk: %s!\n", targetModule->filePath);
#endif
		return FALSE;
	}

	inMemoryTextSectionHeader = getTextSection(targetModule->moduleBase);
	onDiskTextSectionHeader = getTextSection(targetModule->hTargetDllOnDiskMappingAddress);

	// if we couldn't find one of the text sections - error
	if (inMemoryTextSectionHeader == NULL || onDiskTextSectionHeader == NULL) {
		printf("[!] %#X (%ls): no text section found. Skipping the module.\n", targetModule->hModule, targetModule->moduleName);
		return TRUE;
	}
		

	// if text section sizes don't match - error
	if (inMemoryTextSectionHeader->Misc.VirtualSize != onDiskTextSectionHeader->Misc.VirtualSize)
		return FALSE;

	// calculate the actual section locations
	onDiskTextSection = onDiskTextSectionHeader->VirtualAddress + (DWORD_PTR)targetModule->hTargetDllOnDiskMappingAddress;
	inMemoryTextSection = inMemoryTextSectionHeader->VirtualAddress + targetModule->moduleBase;


	while (TRUE) {
		// compare on-disk .text section with the one in memory
		memcmpResult = memcmpCustom(onDiskTextSection, inMemoryTextSection, inMemoryTextSectionHeader->Misc.VirtualSize, memcmpResult);
		// if sections don't match - add the mismatch RVA to the changed list
		if (memcmpResult != -1) {
			current = (modifiedRVAListNode*)malloc(sizeof(modifiedRVAListNode));
			// if head element of the list hasn't been initialized yet - let's make the current our head
			if (head == NULL)
				head = current;
			// if the list has been initiazed already - let's update the previous element's "next" pointer with our current element
			else
				prev->next = current;
			// calculating modified byte as an RVA relative to the image base: text_section_start + memcmpResult - base address
			current->rva = inMemoryTextSection + memcmpResult - targetModule->moduleBase;
			current->next = NULL;
			prev = current;
		}
		else {
			// if the rest is identical - break
			break;
		}
	}

	// update modifiedRVAsLength value for tbe target mineSweeperModuleInfo sttruct
	targetModule->modifiedRVAsLength = getModifiedRVAListLength(head);

	// if we have modified RVAs, let's initialize our modifiedRVAs array
	if (targetModule->modifiedRVAsLength != 0) {
		targetModule->modifiedRVAs = (PDWORD)malloc(sizeof(DWORD) * targetModule->modifiedRVAsLength);

		//transfer the list elements to an array
		// if moveModifiedRVAListToArray returns false - we hit an array overlfow and something must be wrong - return false
		if (!moveModifiedRVAListToArray(head, targetModule->modifiedRVAs, targetModule->modifiedRVAsLength)) {
			cleanModifiedRVAList(head);
			return FALSE;
		}

		// now, let's populate our unhooked and hooked RVA values
		if (!populateHookedAndUnhookedRVAValues(targetModule)) {
			cleanModifiedRVAList(head);
			return FALSE;
		}

		// lastly, let's build our hooked functions list
		// if we get 0 functions at this stage - something went wrong so pull back
		if (0 == buildHookedFunctionsArray(targetModule)) {
			cleanModifiedRVAList(head);
			return FALSE;
		}
	}


	// now, we don't need our linked list anymore, let's clean it up
	cleanModifiedRVAList(head);

	

	return TRUE;
}

// populates hookedRVAValues and unhookedRVAValues arrays
// we store hooked RVA values just in case we want to re-hook the module later on
// returns FALSE in case pre-requisites are not avalailable
BOOL populateHookedAndUnhookedRVAValues(mineSweeperModuleInfo* targetModule) {
	if (targetModule->modifiedRVAsLength < 1 || targetModule->moduleBase == NULL || targetModule->hTargetDllOnDiskMappingAddress == NULL)
		return FALSE;
	
	DWORD length = targetModule->modifiedRVAsLength;
	DWORD_PTR memoryBase = targetModule->moduleBase;
	DWORD_PTR onDiskBase = (DWORD_PTR)targetModule->hTargetDllOnDiskMappingAddress;
	DWORD tempRVA;
	BYTE* hookedRVATempValue;
	BYTE* unhookedRVATempValue;

	// allocate memory for both arrays
	targetModule->hookedRVAValues = malloc(length);
	targetModule->unhookedRVAValues = malloc(length);

	// now go through each RVA and populate both hooked and unhooked values
	for (DWORD i = 0; i < length; i++) {
		tempRVA = targetModule->modifiedRVAs[i];
		hookedRVATempValue = memoryBase + tempRVA;
		unhookedRVATempValue = onDiskBase + tempRVA;
		targetModule->hookedRVAValues[i] = *hookedRVATempValue;
		targetModule->unhookedRVAValues[i] = *unhookedRVATempValue;
	}

	return TRUE;
}

// Empties ModifiedRVAList by freeing each memeber
void cleanModifiedRVAList(modifiedRVAListNode* head) {
	modifiedRVAListNode* current = head, * next = current;
	while (next != NULL) {
		current = next;
		next = next->next;
		free(current);
	}
}


// Move List members to an array
// Returns false in case of array overflow
BOOL moveModifiedRVAListToArray(modifiedRVAListNode* head, PDWORD array, DWORD arrayLength) {
	DWORD counter = 0;
	modifiedRVAListNode* next = head;
	while (next != NULL) {
		// if we are going over the array length - stop and return false
		if (counter >= arrayLength)
			return FALSE;

		array[counter] = next->rva;
		counter++;
		next = next->next;
	}

	return TRUE;

}

// Locates a module's Export Directory Table - takes module handle (module base address) as the only parameter.
// Returns NULL in case of an error
// code inspired by https://stackoverflow.com/questions/2273603/getting-ordinal-from-function-name-programmatically
PIMAGE_EXPORT_DIRECTORY getExportDirectoryTable(HMODULE module) {

	DWORD_PTR               base; // base address of module
	PIMAGE_FILE_HEADER      cfh;  // COFF file header
	PIMAGE_EXPORT_DIRECTORY edt;  // export directory table (EDT)
	DWORD                   rva;  // relative virtual address of EDT
	PIMAGE_DOS_HEADER       mds;  // MS-DOS stub
	PIMAGE_OPTIONAL_HEADER64  oh64;   // so-called "optional" header
	PIMAGE_OPTIONAL_HEADER32 oh32; // 32-bit version of the oh
	PDWORD                  sig;  // PE signature

	// Start at the base of the module. The MS-DOS stub begins there.
	base = (DWORD_PTR)module;
	mds = (PIMAGE_DOS_HEADER)module;

	// Get the PE signature and verify it.
	sig = (DWORD*)(base + mds->e_lfanew);
	if (IMAGE_NT_SIGNATURE != *sig) {
		// Bad signature -- invalid image or module handle
		return NULL;
	}

	// Get the COFF file header.
	cfh = (PIMAGE_FILE_HEADER)(sig + 1);

	// Check the architecture of the binary and cast to an appropriate optional header
	// if it's a 64-bit binary - use the 64-bit optional header struct, if 32-bit - use 32 one.
	if (cfh->Machine == IMAGE_FILE_MACHINE_AMD64) {
		oh64 = (PIMAGE_OPTIONAL_HEADER64)(cfh + 1);
		if (IMAGE_DIRECTORY_ENTRY_EXPORT >= oh64->NumberOfRvaAndSizes) {
			// This image doesn't have an export directory table.
			return NULL;
		}
		rva = oh64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		edt = (PIMAGE_EXPORT_DIRECTORY)(base + rva);


		return edt;
	}
	else if (cfh->Machine == IMAGE_FILE_MACHINE_I386) {
		oh32 = (PIMAGE_OPTIONAL_HEADER32)(cfh + 1);
		if (IMAGE_DIRECTORY_ENTRY_EXPORT >= oh32->NumberOfRvaAndSizes) {
			// This image doesn't have an export directory table.
			return NULL;
		}
		rva = oh32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
		edt = (PIMAGE_EXPORT_DIRECTORY)(base + rva);

		return edt;
	}
	
	//if it's neither x64 or x32, then we are not ready to deal with it :( 
	return NULL;

}


// Count the number of elements in the modifiedRVAListNode list
DWORD getModifiedRVAListLength(modifiedRVAListNode* head) {
	DWORD counter = 0;
	modifiedRVAListNode* next = head;

	while (next != NULL) {
		counter++;
		next = next->next;
	}

	return counter;
}

// Takes a module handle (module base address) and returns a pointer to it's .text section
PIMAGE_SECTION_HEADER getTextSection(HMODULE module) {
	//DOS header = module base
	PIMAGE_DOS_HEADER pDOSHeader = module;

	// get the NT header - i took PBYTE cast inspriation from here https://stackoverflow.com/questions/2273603/getting-ordinal-from-function-name-programmatically
	PIMAGE_NT_HEADERS ntHeader = (PBYTE)module + pDOSHeader->e_lfanew;

	// check if we get a valide PE signature (PE\0\0)
	if (ntHeader->Signature != IMAGE_NT_SIGNATURE)
		return NULL;

	//coff file header to get our size of optional header value
	PIMAGE_FILE_HEADER coffFileHeader = &ntHeader->FileHeader;

	WORD sizeOfOptionalheader = coffFileHeader->SizeOfOptionalHeader;

	//optional header is located 0x18 bytes after the start of the NT header
	PIMAGE_OPTIONAL_HEADER optionalHeader = (PBYTE)ntHeader + 0x18;

	PIMAGE_SECTION_HEADER sectionHeaders = (PBYTE)optionalHeader + sizeOfOptionalheader;

	// check if the target image has any sections. if there are 0 sections - return NULL
	if (coffFileHeader->NumberOfSections < 1)
		return NULL;

	// if there are some sections, let's enum them
	for (int i = 0; i < coffFileHeader->NumberOfSections; i++) {
		// enumerate available sections until we find our .text section
		if (strcmp(sectionHeaders[i].Name, ".text") == 0)
			return &sectionHeaders[i];
	}

	// if we didn't find the .text section - return NULL
	return NULL;

}

/*
CUstom memcmp function that will compare two buffers and return an index value of the first mismatch identfied.
Returns -1 if the buffers are identical
size_t start value can specify the comparison start offset (used by the sweepModule function)
*/
int memcmpCustom(const void* s1, const void* s2, size_t n, size_t start) {

	BYTE* array1 = s1;
	BYTE* array2 = s2;

	if (n < 1)
	{
		return -1;
	}

	// if start is 0 - set i to 0, if start is not 0, then i = start + 1
	if (start == 0) {
		for (size_t i = 0; i < n; i++) {
			if (array1[i] != array2[i])
				return i;
		}
	}
	else {
		for (size_t i = start + 1; i < n; i++) {
			if (array1[i] != array2[i])
				return i;
		}
	}

	return -1;

}


/*
Take a memory address (provided by the memcmpCustom function) and find a closest ordinal in the provided EAT. If used properly, the function will allow to find the hooked EAT ordinal.
Returns -1 in a case all RVAs in the EAT are past the target byte memory address.
*/
int findClosestEAT_RVA(DWORD_PTR targetByte, DWORD_PTR moduleBase, PDWORD eat, size_t eat_length) {
	int ordinal = -1;
	// a variable to hold currrent difference between the closest EAT function and our target byte. This will be considered the smalles difference currently found
	// using long long to avoid variable overflow since DWORD_PTR is unsigned long
	long long currentDifference = NULL;
	long long tempDifference = NULL;

	for (int i = 0; i < eat_length; i++) {

		// find the difference between current eat function memory address and our target byte in the .text section
		tempDifference = targetByte - (moduleBase + eat[i]);

		// if function RVA + module base are greater than our targete byte - skip since the function appears in the .text secttion after our targeet byte
		if (tempDifference < 0)
			continue;

		// if currentDifference is NULL then take this function as our best match, otherwise take it if the difference is smaller than the current best match
		if (currentDifference == NULL || tempDifference < currentDifference) {
			currentDifference = tempDifference;
			ordinal = i;

			// if tempDifference is zero, it means this is the best match possible at this point (i.e: the hook is at the start of the function) and we can stop here 
			if (tempDifference == 0)
				break;
		}
	}

	return ordinal;
}

PDWORD getExportAddressTable(HMODULE module) {
	PDWORD eat; // export address table
	PIMAGE_EXPORT_DIRECTORY edt; // export directory table
	PBYTE moduleBase; // module base address - convenience variable

	moduleBase = (PBYTE)module;

	edt = getExportDirectoryTable(module);

	eat = edt->AddressOfFunctions + moduleBase;

	return eat;
}

PWORD getExportOrdinalTable(HMODULE module) {
	PWORD eot; // export ordinal table
	PIMAGE_EXPORT_DIRECTORY edt; // export directory table
	PBYTE moduleBase; // module base address - convenience variable

	moduleBase = (PBYTE)module;

	edt = getExportDirectoryTable(module);

	eot = edt->AddressOfNameOrdinals + moduleBase;

	return eot;
}

PDWORD getNamePointerTable(HMODULE module) {
	PDWORD npt; // name pointer table

	PIMAGE_EXPORT_DIRECTORY edt; // export directory table
	DWORD_PTR moduleBase; // module base address - convenience variable

	moduleBase = (DWORD_PTR)module;

	edt = getExportDirectoryTable(module);

	npt = moduleBase + edt->AddressOfNames;

	return npt;

}

// Takes a module handle (module base address) and an EOT ordinal to converse that to a function name
// Returns NULL in case of an error
char* EOTIndexToFuncNameMineSweeper(mineSweeperModuleInfo* targetModule, DWORD ordinal) {
	char* functionName; // variable to hold our function name pointer
	PDWORD npt; // name pointer table
	PIMAGE_EXPORT_DIRECTORY edt; // export directory table
	DWORD_PTR moduleBase; // module base address - convenience variable

	moduleBase = targetModule->moduleBase;

	edt = targetModule->edt;

	// check for ordinal out of bounds 
	if (edt->NumberOfNames < ordinal || ordinal < 0) {
		return NULL;
	}

	npt = targetModule->npt;

	functionName = moduleBase + npt[ordinal];

	return functionName;
}

// Takes a module handle (module base address) and an EOT ordinal to converse that to a function name
// Returns NULL in case of an error
char* EOTIndexToFuncName(HMODULE module, DWORD ordinal) {
	char* functionName; // variable to hold our function name pointer
	PDWORD npt; // name pointer table
	PIMAGE_EXPORT_DIRECTORY edt; // export directory table
	DWORD_PTR moduleBase; // module base address - convenience variable

	moduleBase = (DWORD_PTR)module;

	edt = getExportDirectoryTable(module);

	// check for ordinal out of bounds 
	if (edt->NumberOfNames < ordinal || ordinal < 0) {
		return NULL;
	}

	npt = moduleBase + edt->AddressOfNames;

	functionName = moduleBase + npt[ordinal];

	return functionName;
}

// Take an EAT index and try to find an element in the provided EOT array that matches the EAT index value
// Returns -1 if no match was found
int EATIndexToEOTIndex(WORD eatIndex, PWORD eot, DWORD eotLength) {
	int index = -1;

	for (DWORD i = 0; i < eotLength; i++) {
		if (eot[i] == eatIndex) {
			index = i;
			break;
		}
	}

	return index;
}


VOID cleanUpModule(mineSweeperModuleInfo* targetModule) {

	if (targetModule->filePath != NULL)
		free(targetModule->filePath);

	if (targetModule->hTargetDllOnDiskMappingAddress != NULL)
		UnmapViewOfFile(targetModule->hTargetDllOnDiskMappingAddress);

	if (targetModule->hTargetDllOnDiskFileMapping != NULL)
		CloseHandle(targetModule->hTargetDllOnDiskFileMapping);

	if (targetModule->hTargetDllOnDisk != NULL)
		CloseHandle(targetModule->hTargetDllOnDisk);

	if (targetModule->modifiedRVAsLength > 0)
		free(targetModule->modifiedRVAs);

	if (targetModule->hookedFunctionsLength > 0) {
		// first release modifiedRVAsIndexes array for each hooked function
		for (short i = 0; i < targetModule->hookedFunctionsLength; i++) {
			free(targetModule->hookedFunctions[i].modifiedRVAsIndexes);
		}
		// now free the entire hooked functions array
		free(targetModule->hookedFunctions);
	}
	
	// if remote process
	// note: hModule and moduleBase should be the same if it's a local process, so that's what we are checking here
	if ((DWORD_PTR)targetModule->hModule != targetModule->moduleBase) {
		free(targetModule->moduleBase);
	}

	free(targetModule);
}

BOOL mapFileFromDisk(mineSweeperModuleInfo* targetModule) {
	// append "\\?\globalroot" since CreateFileW doesn't accept a canonical path returned by GetMappedFileNameW winapi function. The idea was taken from https://stackoverflow.com/questions/48178586/how-to-disable-wow64-file-system-redirection-for-getmodulefilenameex
	wchar_t tempString[filePathLength] = L"\\\\?\\globalroot";

	if (0 != wcscat_s(tempString, filePathLength, targetModule->filePath))
		return FALSE;


	targetModule->hTargetDllOnDisk = CreateFileW(tempString, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);

	if (targetModule->hTargetDllOnDisk == INVALID_HANDLE_VALUE)
		return FALSE;

	// thanks to @slaeryan for SEC_IMAGE_NO_EXECUTE tip B-) https://twitter.com/slaeryan/status/1336959057232449536
	targetModule->hTargetDllOnDiskFileMapping = CreateFileMapping(targetModule->hTargetDllOnDisk, NULL, PAGE_READONLY | SEC_IMAGE_NO_EXECUTE, 0, 0, NULL);

	if (targetModule->hTargetDllOnDiskFileMapping == NULL)
		return FALSE;

	targetModule->hTargetDllOnDiskMappingAddress = MapViewOfFile(targetModule->hTargetDllOnDiskFileMapping, FILE_MAP_READ, 0, 0, 0);

	if (targetModule->hTargetDllOnDiskMappingAddress == NULL)
		return FALSE;

	return TRUE;

}

/*
Wrapper for EnumProcessModulesEx. Obtains a process' modules list. Works with both local and remote processes. 
Takes a target module handle, a pointer to modules array and a pointer to a DWORD for the array's length
Returns TRUE if successful.
Warning: Don't forget to free the modules array once you are done with it!
*/
BOOL getProcessModules(HANDLE hProcess, HMODULE** modules, DWORD* modulesLength) {
	
	

	DWORD tempModulesLength;

	// setting modules length to 0 just in case it's uninitialized yet
	*modulesLength = 0;

	// Let's find out how many modules are there
	if (!EnumProcessModulesEx(hProcess, NULL, NULL, &tempModulesLength, LIST_MODULES_ALL)) {
#if _DEBUG
		printf("[!] Failed to EnumProcessModulesEx!\n");
#endif
		return FALSE;
	}
	
	// allocate modules array space
	*modules = malloc(sizeof(HMODULE) * tempModulesLength);

	// set modulesLength
	*modulesLength = tempModulesLength;
	
	// Now, let's actually get our target modules
	// Notice second condition in the if statemnt below - we want to make sure that tempModulesLength > *modulesLength is FALSE so we don't miss any modules
	if (!EnumProcessModulesEx(hProcess, *modules, *modulesLength, &tempModulesLength, LIST_MODULES_ALL) || tempModulesLength > *modulesLength) {
#if _DEBUG
		printf("[!] Failed to EnumProcessModulesEx for the second time - module count must have changed just now!\n");
#endif
		return FALSE;
	}
	
	// update module length with the actual module length as per https://docs.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-enumprocessmodulesex
	// "To determine how many modules were enumerated by the call to EnumProcessModulesEx, divide the resulting value in the lpcbNeeded parameter by sizeof(HMODULE)."
	*modulesLength = *modulesLength / sizeof(HMODULE);

	return TRUE;
}


/*
Prints each module handle and it's canonical path for the target process.
*/
void printProcessModules(HANDLE hProcess, HMODULE* modules, DWORD modulesLength) {
	if (modulesLength < 1) {
		printf("[!] No modules to print. \n");
		return;
	}

	for (DWORD i = 0; i < modulesLength; i++) {
		PWSTR tempFileName[filePathLength] = { 0 }; // create a temporary PWSTR to be used with file name retrieval
		GetMappedFileNameW(hProcess, modules[i], tempFileName, filePathLength);
		printf("\t%d) %#X - %ls\n", i+1, modules[i], tempFileName);
	}
	

}

/*
Searches for modules that contain a specified string in their path. 
Returns FALSE in case of an error.
Warning: Don't forget to free the matchedModules array once you are done with it!
*/
BOOL findModuleHandleByFilePath(HANDLE hProcess, HMODULE* modules, DWORD modulesLength, HMODULE ** matchedModules, DWORD * matchedModulesLength, wchar_t * searchString) {
	
	// declaring a quick linked list structure since we don't know how many matches we are going to get
	typedef struct matchedModuleStruct {
		struct matchedModuleStruct* next;
		HMODULE hModule;
	} matchedModulesNode;

	// initialize our list head
	matchedModulesNode head = { 0 };
	// initialize our list pointers
	matchedModulesNode* prev = NULL, * current = NULL;
	// create a temporary PWSTR to be used with file name retrieval
	PWSTR tempFileName[filePathLength] = { 0 }; 
	DWORD fileNameLength;
	wchar_t* tempSearchPointer = NULL;
	// set this to zero just in case
	*matchedModulesLength = 0; 

	// if searchString is empty - return FALSE
	if (wcslen(searchString) < 1)
		return FALSE;

	for (DWORD i = 0; i < modulesLength; i++) {
		fileNameLength = GetMappedFileNameW(hProcess, modules[i], tempFileName, filePathLength);

		// if we get a filename back, let's search our string within it
		if (fileNameLength > 0) {
			tempSearchPointer = wcsstr(tempFileName, searchString);
			
			//if we found a match
			if (tempSearchPointer != NULL) {
				// increase our matched modules counter
				(*matchedModulesLength)++;

				// add an item to our linked list
				// if it's our first match, updated the head, otherwise create a new list element
				if (prev == NULL) {
					head.hModule = modules[i];

					prev = &head;
				}
				else {
					current = malloc(sizeof(matchedModulesNode));
					
					prev->next = current;

					current->hModule = modules[i];

					current->next = NULL;

					prev = current;
				}
			}
		}
	}

	// now let's check if find any matches. If not then we are done here
	if (*matchedModulesLength < 1)
		return TRUE;

	// seems like we got some matched, let's initialize an array of HMODULES 
	*matchedModules = malloc(sizeof(HMODULE) * *matchedModulesLength);

	// populate our matched modules array
	current = &head;
	for (WORD i = 0; i < *matchedModulesLength; i++) {
		(*matchedModules)[i] = current->hModule;
		current = current->next;
	}

	// clean up our linked list (if there are more than 1 element)
	if (*matchedModulesLength > 1) {
		current = head.next;

		while (current != NULL) {
			prev = current;
			current = current->next;
			free(prev);
		}
		
	}

	return TRUE;
}


/*
Takes PID (NULL for local process) and the module name (e.g.: "ntdll", "kernel32.dll" or just ".dll" if you want to target every loaded DLL) to sweep them for user-land hooks and unhook any module that found to be hooked.
If moduleName is NULL, sweep and unhook all DLL's
The function will handle mutliple modules if they match the moduleName string or if there are multiple modules with the same name (e.g.: WOW64 and x64 NTDLL).
Returns FALSE in case of any error.
*/
BOOL unhookProcessModules(DWORD pid, wchar_t* moduleName) {
	HANDLE hProcess = NULL;
	HMODULE* modulesArray = NULL;
	HMODULE* matchedModulesArray = NULL;
	DWORD modulesArrayLength = 0;
	DWORD matchedModulesArrayLength = 0;
	DWORD currentPID = GetCurrentProcessId();

	// basic PID check
	if (pid < 0 || (pid % 4 != 0)) {
		printf("[!] Invalid PID!\n");
		return FALSE;
	}


	// get PID handle - check if we targetting local or remote process here
	if (pid == NULL) {
		hProcess = GetCurrentProcess();
		pid = currentPID;
	}
	else if (pid == currentPID) {
		hProcess = GetCurrentProcess();
	}
	else {
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	}

	printf("\n[*] Target PID - %d\n", pid);


	// in case we failed to obtain target process handle
	if (hProcess == NULL) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d handle! Last error: %d\n", pid, GetLastError());
#endif
		return FALSE;
	}

	// if moduleName is NULL - set it to our default ".dll" to go through all modules
	if (moduleName == NULL)
		moduleName = L".dll";

	printf("[*] Enumerating loaded modules\n");

	// get modules
	if (!getProcessModules(hProcess, &modulesArray, &modulesArrayLength)) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d modules! Last error: %d\n", pid, GetLastError());
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		return FALSE;
	} 
	else {
		printf("[*] Found %d loaded modules.\n", modulesArrayLength);
	}

	// get matched modules
	if (!findModuleHandleByFilePath(hProcess, modulesArray, modulesArrayLength, &matchedModulesArray, &matchedModulesArrayLength, moduleName)) {
#if _DEBUG
		printf("[!] File path to module handle function failed!%d\n");
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		return FALSE;
	}

	// free modules array - we don't need it anymore
	free(modulesArray);


	printf("[*] Looking for loaded modules that contain \"%ls\" in their path.\n", moduleName);

	if (matchedModulesArrayLength < 1) {
		printf("[!] No matches found.\n");
	}
	else {
		printf("[*] %d matches out of %d loaded modules:\n", matchedModulesArrayLength, modulesArrayLength);
	}


	// for each matched module:
	for (DWORD i = 0; i < matchedModulesArrayLength; i++) {
		// initialize MineSweepr module info struct
		mineSweeperModuleInfo* targetModule = initializeMineSweeperModuleInfo(matchedModulesArray[i], hProcess);

		// if there was an error - skip the module
		if (targetModule == NULL) {
			printf("[!] Module handle %#X - Error initializing\n\n", matchedModulesArray[i]);
			continue;
		}

		// sweep for hooks - skip in case of errors
		if (!sweepModule(targetModule)) {
			printf("[!] Failed to sweep module handle %#X - %ls\n\n", matchedModulesArray[i], targetModule->filePath);
			continue;
		}

		// if modified RVAs were detected in the .text section of the target module
		if (targetModule->modifiedRVAsLength > 0) {
			if (!isTextSectionOverwritten(targetModule)) {
				printf("[*] A hooked module found! \n\tModule name: %ls\n\tModule handle: %#X \n\tModule canonical path: %ls\n\tBytes modified: %d \n", targetModule->moduleName, matchedModulesArray[i], targetModule->filePath, targetModule->modifiedRVAsLength);
				// now unhook them all
				if (!unhookOrRehookModule(targetModule, UNHOOK))
					printf("[!] Unhooking %ls failed!\n\n", targetModule->moduleName);
				else
					printf("[*] Unhooking %ls succeeded!\n\n", targetModule->moduleName);
			}
			else {
				printf("[!] %#X (%ls): unsually large .text section overwrite detected, the module was skipped. Bytes modified: %d \n", matchedModulesArray[i], targetModule->moduleName, targetModule->modifiedRVAsLength);
			}
		}
		// cleanUp mineSweeperModuleInfo
		cleanUpModule(targetModule);
	}

	printf("\n");

	// clean Up matched modules array
	free(matchedModulesArray);

	// free process handle (if remote process)
	if (pid != currentPID)
		CloseHandle(hProcess);

	return TRUE;
}

/*
Takes target pid for the process  (NULL for local process), optional module name (NULL for all .dll) that needs to be re-hooked and a hooked pid (NULL for local process) that is still hooked which will be used as a reference to restore hooks.
E.g: pid = our unhooked process, moduleName = targetModule to be re-hooked, hookedPID = a process that still has hooks applied to it (must be the same architecture as our target pid!)
Returns FALSE in case of error
NOTE 1: hookedPID and pid cannot match
NOTE 2: the target modules have to be currently loaded by both pid and hookedPID and their canonical path should match
*/
BOOL rehookProcessModules(DWORD pid, wchar_t* moduleName, DWORD hookedPID) {
	// variables for our pid
	HANDLE hProcess = NULL;
	HMODULE* modulesArray = NULL;
	HMODULE* matchedModulesArray = NULL;
	DWORD modulesArrayLength = 0;
	DWORD matchedModulesArrayLength = 0;

	// variables for our hookedPID
	HANDLE hHookedProcess = NULL; 
	HMODULE* hookedModulesArray = NULL;
	HMODULE* hookedMatchedModulesArray = NULL;
	DWORD hookedModulesArrayLength = 0;
	DWORD hookedMatchedModulesArrayLength = 0;

	DWORD currentPID = GetCurrentProcessId();
	HANDLE tempProcessHandle = NULL;

	// basic PID check
	if (pid < 0 || (pid % 4 != 0) || pid == hookedPID || hookedPID < 0 || hookedPID % 4 != 0) {
		printf("[!] Invalid PID!\n");
		return FALSE;
	}
		

	// get PID handle - check wether we are targetting a local or a remote process 
	if (pid == NULL) {
		hProcess = GetCurrentProcess();
		pid = currentPID;
	}
	else if (pid == currentPID) {
		hProcess = GetCurrentProcess();
	}
	else {
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, pid);
	}

	// open a handle to our hookedPID
	if (hookedPID == NULL) {
		hHookedProcess = GetCurrentProcess();
		hookedPID = currentPID;
	}
	else if (hookedPID == currentPID) {
		hHookedProcess = GetCurrentProcess();
	}
	else {
		// minimal permission requirements
		hHookedProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, hookedPID);
	}

	printf("\n[*] Re-hook target PID: %d\n[*] Hooks donor PID: %d\n", pid, hookedPID);

	// in case we failed to obtain our target process handles
	if (hProcess == NULL) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d handle! \n", pid);
#endif
		return FALSE;
	}
	else if (hHookedProcess == NULL){
#if _DEBUG
		printf("[!] Failed to obtain PID %d handle! \n", hookedPID);
#endif
		return FALSE;
	}

	printf("[*] Enumerating loaded modules\n");

	// get modules pid
	if (!getProcessModules(hProcess, &modulesArray, &modulesArrayLength)) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d modules! Last error: %d\n", pid, GetLastError());
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		if (hookedPID != currentPID)
			CloseHandle(hHookedProcess);

		return FALSE;
	}
	else {
		printf("[*] Found %d loaded modules by PID %d\n", modulesArrayLength, pid);
	}
	

	// get modules hookedPID
	if (!getProcessModules(hHookedProcess, &hookedModulesArray, &hookedModulesArrayLength)) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d modules! Last error: %d\n", hookedPID, GetLastError());
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		if (hookedPID != currentPID)
			CloseHandle(hHookedProcess);

		return FALSE;
	}
	else {
		printf("[*] Found %d loaded modules by PID %d\n", hookedModulesArrayLength, hookedPID);
	}

	// if moduleName is NULL - set it to our default ".dll" to go through all modules
	if (moduleName == NULL)
		moduleName = L".dll";

	printf("[*] Looking for loaded modules that contain \"%ls\" in their path.\n", moduleName);

	// get matched modules for pid
	if (!findModuleHandleByFilePath(hProcess, modulesArray, modulesArrayLength, &matchedModulesArray, &matchedModulesArrayLength, moduleName)) {
#if _DEBUG
		printf("[!] File path to module handle function failed!%d\n");
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		if (hookedPID != currentPID)
			CloseHandle(hHookedProcess);

		return FALSE;
	}

	if (matchedModulesArrayLength < 1) {
		printf("[!] PID %d: No matches found.\n", pid);
	}
	else {
		printf("[*] PID %d: %d matches out of %d loaded modules.\n", pid, matchedModulesArrayLength, modulesArrayLength);
	}

	// get matched modules for hookedPID
	if (!findModuleHandleByFilePath(hHookedProcess, hookedModulesArray, hookedModulesArrayLength, &hookedMatchedModulesArray, &hookedMatchedModulesArrayLength, moduleName)) {
#if _DEBUG
		printf("[!] File path to module handle function failed!%d\n");
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		if (hookedPID != currentPID)
			CloseHandle(hHookedProcess);

		return FALSE;
	}

	if (hookedMatchedModulesArrayLength < 1) {
		printf("[!] PID %d: No matches found.\n", hookedPID);
	}
	else {
		printf("[*] PID %d: %d matches out of %d loaded modules.\n", hookedPID, hookedMatchedModulesArrayLength, hookedModulesArrayLength);
	}

	// free modules array - we don't need them anymore
	free(modulesArray);
	free(hookedModulesArray);
		
	// if we are working with module filter, re-assign the filtered vars
	modulesArray = matchedModulesArray;
	modulesArrayLength = matchedModulesArrayLength;
	hookedModulesArray = hookedMatchedModulesArray;
	hookedModulesArrayLength = hookedMatchedModulesArrayLength;
	
	

	// for each matched module - check if hookedPID has that module hooked, if so, re-hook it for our target pid:
	for (DWORD i = 0; i < hookedModulesArrayLength; i++) {
		// initialize MineSweepr module info struct
		mineSweeperModuleInfo* targetModule = initializeMineSweeperModuleInfo(hookedModulesArray[i], hHookedProcess);

		// if there was an error - skip the module
		if (targetModule == NULL) {
			printf("[!] Module handle %#X - Error initializing\n\n", hookedModulesArray[i]);
			continue;
		}

		// sweep for hooks - skip in case of errors
		if (!sweepModule(targetModule)) {
			printf("[!] Failed to sweep module handle %#X - %ls\n\n", hookedModulesArray[i], targetModule->filePath);
			continue;
		}


		// if modified RVAs were detected in the .text section of the target module
		if (targetModule->modifiedRVAsLength > 0) {

			if (!isTextSectionOverwritten(targetModule)) {
				printf("[*] A hooked module found! \n\tModule name: %ls\n\tModule handle: %#X \n\tModule canonical path: %ls\n\tBytes modified: %d \n", targetModule->moduleName, hookedModulesArray[i], targetModule->filePath, targetModule->modifiedRVAsLength);

				// check if our target PID also has this module loaded
				if (containsModuleHandle(hookedModulesArray[i], modulesArray, modulesArrayLength)) {

					printf("[*] Re-hooking %ls in PID %d..\n", targetModule->moduleName, pid);

					// cheap trick: substituing hookedPID handle with the pid one - to avoid initializing another mineSweeperModuleInfo struct
					tempProcessHandle = targetModule->hProcess;
					targetModule->hProcess = hProcess;

					// if there are any hooks - unhook 
					if (!unhookOrRehookModule(targetModule, REHOOK))
						printf("[!] Re-hooking failed!\n\n");
					else
						printf("[*] Re-hooking succeeded!\n\n");

					// re=assigning the old process handle back 
					targetModule->hProcess = tempProcessHandle;
				}

				else {
					printf("[!] %#X - %ls - was found to be hooked in %d but was not present in %d.\n", hookedModulesArray[i], targetModule->moduleName, hookedPID, pid);
				}
			}
			else {
				printf("[!] %#X (%ls): unsually large .text section overwrite detected, the module was skipped. Bytes modified: %d \n", matchedModulesArray[i], targetModule->moduleName, targetModule->modifiedRVAsLength);
			}
			

		}
		
		// cleanUp mineSweeperModuleInfo
		cleanUpModule(targetModule);
	}
	printf("\n");

	// clean Up matched modules array
	free(modulesArray);
	free(hookedModulesArray);

	// free process handle (if remote process)
	if (pid != currentPID)
		CloseHandle(hProcess);

	if (hookedPID != currentPID)
		CloseHandle(hHookedProcess);

	return TRUE;
}

/*
Searches array of module handles (moduleArray of moduleArrayLength) for existance of a specified module handle (targetModule)
*/
BOOL containsModuleHandle(HMODULE targetModule, HMODULE* moduleArray, DWORD moduleArrayLength) {
	
	for (DWORD i = 0; i < moduleArrayLength; i++) {
		if (targetModule == moduleArray[i])
			return TRUE;
	}

	return FALSE;
}

/*
Takes PID (NULL for local process) and the module name (e.g.: "ntdll", "kernel32.dll" or even just ".dll" if you want to check all loaded DLLs) to sweep them for user-land hooks.
If moduleName is NULL, sweep all .dll
The function will handle mutliple modules if they match the moduleName string or if there are multiple modules with the same name (e.g.: WOW64 and x64 NTDLL).
Returns FALSE in case of any error.
*/
BOOL sweepProcessModules(DWORD pid, wchar_t* moduleName) {
	HANDLE hProcess = NULL;
	HMODULE* modulesArray = NULL;
	HMODULE* matchedModulesArray = NULL;
	DWORD modulesArrayLength = 0;
	DWORD matchedModulesArrayLength = 0;
	DWORD currentPID = GetCurrentProcessId();
	BOOL hooked = FALSE;

	// basic PID check
	if (pid < 0 || (pid % 4 != 0)) {
		printf("[!] Invalid PID!\n");
		return FALSE;
	}
		



	// get PID handle - check if we targetting local or remote process here
	if (pid == NULL) {
		hProcess = GetCurrentProcess();
		pid = currentPID;
	}
	else if (pid == currentPID) {
		hProcess = GetCurrentProcess();
	}
	else {
		// note: asking for the minimal required permissions
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	}

	printf("\n[*] Target PID - %d\n", pid);


	// in case we failed to obtain target process handle
	if (hProcess == NULL) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d handle! Last error: %d\n", pid, GetLastError());
#endif
		return FALSE;
	}

	// if moduleName is NULL - set it to our default - ".dll" to sweep all modules
	if (moduleName == NULL)
		moduleName = L".dll";
	
	printf("[*] Enumerating loaded modules\n");

	// get modules
	if (!getProcessModules(hProcess, &modulesArray, &modulesArrayLength)) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d modules! Last error: %d\n", pid, GetLastError());
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		return FALSE;
	} 
	else {
		printf("[*] Found %d loaded modules.\n", modulesArrayLength);
	}

	printf("[*] Looking for loaded modules that contain \"%ls\" in their path.\n", moduleName);

	// get matched modules
	if (!findModuleHandleByFilePath(hProcess, modulesArray, modulesArrayLength, &matchedModulesArray, &matchedModulesArrayLength, moduleName)) {
#if _DEBUG
		printf("[!] File path to module handle function failed!%d\n");
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);

		return FALSE;
	}

	// free modules array - we don't need it anymore
	free(modulesArray);


	if (matchedModulesArrayLength < 1) {
		printf("[!] No matches found.\n");
	}
	else {
		printf("[*] %d matches out of %d loaded modules.\n", matchedModulesArrayLength, modulesArrayLength);
	}


	// for each matched module:
	for (DWORD i = 0; i < matchedModulesArrayLength; i++) {
		// initialize MineSweepr module info struct
		mineSweeperModuleInfo* targetModule= initializeMineSweeperModuleInfo(matchedModulesArray[i], hProcess);

		// if there was an error - skip the module
		if (targetModule == NULL) {
			printf("[!] Module handle %#X - Error initializing\n\n", matchedModulesArray[i]);
			continue;
		}

		// sweep for hooks - skip in case of errors
		if (!sweepModule(targetModule)) {
			printf("[!] Failed to sweep the module handle %#X - %ls\n\n", matchedModulesArray[i], targetModule->filePath);
			continue;
		}

		// if modified RVAs were detected in the .text section of the target module
		if (targetModule->modifiedRVAsLength > 0) {
			if (!isTextSectionOverwritten(targetModule)) {
				hooked = TRUE;
				// if there are any hooks - print hooked functions 
				printf("[*] A hooked module found! \n\tModule name: %ls\n\tModule handle: %#X \n\tModule canonical path: %ls\n\tBytes modified: %d \n", targetModule->moduleName, matchedModulesArray[i], targetModule->filePath, targetModule->modifiedRVAsLength);
				printHookedFunctions(targetModule);
				printf("\n");			
			}
			else {
				printf("[!] %#X (%ls): unsually large .text section overwrite detected, the module was skipped. Bytes modified: %d \n", matchedModulesArray[i], targetModule->moduleName, targetModule->modifiedRVAsLength);
			}
			
		}	
				
		// cleanUp mineSweeperModuleInfo
		cleanUpModule(targetModule);
	}

	if (!hooked) {
		printf("[*] No hooked modules found. \n");
	}

	printf("\n");

	// clean Up matched modules array
	free(matchedModulesArray);

	// free process handle (if remote process)
	if (pid != currentPID)
		CloseHandle(hProcess);
	
	return TRUE;

}

/*
Takes target pid and list modules loaded by the process. Optionally, moduleName string can be provided to only list modules that contain provided string in their canonical path
Returns FALSE in case of any errors
*/
BOOL listProcessModules(DWORD pid, wchar_t* moduleName) {
	HANDLE hProcess = NULL;
	HMODULE* modulesArray = NULL;
	HMODULE* matchedModulesArray = NULL;
	DWORD modulesArrayLength = 0;
	DWORD matchedModulesArrayLength = 0;
	DWORD currentPID = GetCurrentProcessId();

	// basic PID check
	if (pid < 0 || (pid % 4 != 0))
		return FALSE;

	// get PID handle - check if we targetting local or remote process here
	if (pid == NULL) {
		hProcess = GetCurrentProcess();
		pid = currentPID;
	}
	else if (pid == currentPID) {
		hProcess = GetCurrentProcess();
	}
	else {
		// note: asking for the minimal required permissions
		hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
	}
		
	printf("\n[*] Target PID - %d\n", pid);

	// in case we failed to obtain target process handle
	if (hProcess == NULL) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d handle! Last error: %d\n", pid, GetLastError());
#endif
		return FALSE;
	}

	printf("[*] Enumerating loaded modules\n");

	// get modules. Return FALSE on fail
	if (!getProcessModules(hProcess, &modulesArray, &modulesArrayLength)) {
#if _DEBUG
		printf("[!] Failed to obtain PID %d modules! Last error: %d\n", pid, GetLastError());
#endif
		// free process handle (if remote process)
		if (pid != currentPID)
			CloseHandle(hProcess);
		return FALSE;
	}

	// if we need to print all modules
	if (moduleName == NULL) {
		printf("[*] Found %d loaded modules.\n", modulesArrayLength);
		printProcessModules(hProcess, modulesArray, modulesArrayLength);
	}
	// if we are looking for specific modules
	else {
		printf("[*] Looking for loaded modules that contain \"%ls\" in their path.\n", moduleName);
		// get matched modules
		if (!findModuleHandleByFilePath(hProcess, modulesArray, modulesArrayLength, &matchedModulesArray, &matchedModulesArrayLength, moduleName)) {
#if _DEBUG
			printf("[!] File path to module handle function failed!%d\n");

#endif
			free(modulesArray);
			// free process handle (if remote process)
			if (pid != currentPID)
				CloseHandle(hProcess);
			return FALSE;
		}
		if (matchedModulesArrayLength < 1) {
			printf("[!] No matches found out of %d loaded modules.\n", modulesArrayLength);
		}
		else {
			printf("[*] %d matches out of %d loaded modules:\n", matchedModulesArrayLength, modulesArrayLength);
			printProcessModules(hProcess, matchedModulesArray, matchedModulesArrayLength);
		}
		
	}

	printf("\n");


	// free modules array - 
	free(modulesArray);
	// free matched modules array
	free(matchedModulesArray);

	// free process handle (if remote process)
	if (pid != currentPID)
		CloseHandle(hProcess);

	return TRUE;

}

/*
Unhooks or re-hooks the target module. Supports both local and remote target processes.

Mode flag options:
	0 - unhook
	1 - re-hook 

Returns TRUE on success.
*/
BOOL unhookOrRehookModule(mineSweeperModuleInfo* targetModule, BYTE mode) {
	
	// check mode flag for validity
	if (mode < UNHOOK || mode > REHOOK)
		return FALSE;

	if (targetModule->modifiedRVAsLength < 1)
		return FALSE;
	
	DWORD oldProtect = 0;
	BYTE * buffer = NULL;

	// I decided to request RWX since my thinking was that changing it to anything else (e.g. RW) may break our target process if it's already running as we do this
	DWORD newProtect = PAGE_EXECUTE_READWRITE;

	// our start address for VirtualProtectEx
	LPVOID start = (DWORD_PTR) targetModule->hModule + targetModule->modifiedRVAs[0];
	
	// number of bytes we need to modify from the start of our address
	SIZE_T numberOfBytes = targetModule->modifiedRVAs[targetModule->modifiedRVAsLength - 1] - targetModule->modifiedRVAs[0];

	// change memory persmissions to allow us to write into the target's process memory space
	if (!VirtualProtectEx(targetModule->hProcess, start, numberOfBytes, newProtect, &oldProtect)) {
#if _DEBUG
		printf("[!] VirtualProtectEx failed!%d\n");
#endif
		return FALSE;
	}

	// now we should have permissions to write, let's go function after function and unhook / re-hook
	for (DWORD i = 0; i < targetModule->hookedFunctionsLength; i++) {
		
		// first, let's get the index value of the hookedFunction's first modified RVA in our modifiedRVAs array
		WORD rvaIndex = targetModule->hookedFunctions[i].modifiedRVAsIndexes[0];

		// select appropriate buffer based on our mode
		if (mode == UNHOOK)
			buffer = &targetModule->unhookedRVAValues[rvaIndex];
		else
			buffer = &targetModule->hookedRVAValues[rvaIndex];
		// if it's a local process, let's overwrite the memory without calling WriteProcessMemory 
		if (targetModule->hProcess == GetCurrentProcess()) {
			for (WORD j = 0; j < targetModule->hookedFunctions[i].modifiedRVAsIndexesCount; j++) {

				rvaIndex = targetModule->hookedFunctions[i].modifiedRVAsIndexes[j];

				BYTE * RVAtoOverwrite = (DWORD_PTR)targetModule->hModule + targetModule->modifiedRVAs[rvaIndex];

				*RVAtoOverwrite = buffer[j];
			}
		}
		// if it's a remote process, we'll have to rely on WriteProcessMemory function
		else {
			// check if all RVAs for our function are consecutive
			if (isConsecutiveRVAs(&targetModule->hookedFunctions[i], targetModule->modifiedRVAs)) {
				// now take that array index and translate it into our start address for our WriteProcessMemory call (module base + first modified RVA for a given function we want to unhook)
				LPVOID writeStartAddress = (DWORD_PTR)targetModule->hModule + targetModule->modifiedRVAs[rvaIndex];

				if (!WriteProcessMemory(targetModule->hProcess, writeStartAddress, buffer, targetModule->hookedFunctions[i].modifiedRVAsIndexesCount, NULL)) {
					// if we failed to write into process memory - pull back
#if _DEBUG
					printf("[!] WriteProcessMemory failed for %ls!%s - %d\n", targetModule->moduleName, targetModule->hookedFunctions[i].functionName, GetLastError());
#endif
					// change the memory permissions back to their original value
					if (!VirtualProtectEx(targetModule->hProcess, start, numberOfBytes, oldProtect, &newProtect)) {
#if _DEBUG
						printf("[!] VirtualProtectEx failed restoring permissions after unhook/re-hook!%d\n");
#endif
					}
					return FALSE;
				}
			}
			// if not all modified RVAs are consecutive, then write each byte at a time - this should be a rare condition
			else {
				for (WORD j = 0; j < targetModule->hookedFunctions[i].modifiedRVAsIndexesCount; j++) {

					rvaIndex = targetModule->hookedFunctions[i].modifiedRVAsIndexes[j];

					LPVOID writeStartAddress = (DWORD_PTR)targetModule->hModule + targetModule->modifiedRVAs[rvaIndex];

					// now write the buffer - notice buffer size is only 1 byte since we are writing 1 byte at a time
					if (!WriteProcessMemory(targetModule->hProcess, writeStartAddress, &buffer[j], 1, NULL)) {
						// if we failed to write into process memory - pull back
#if _DEBUG
						printf("[!] WriteProcessMemory failed for %ls!%s - %d\n", targetModule->moduleName, targetModule->hookedFunctions[i].functionName, GetLastError());
#endif
						// change the memory permissions back to their original value
						if (!VirtualProtectEx(targetModule->hProcess, start, numberOfBytes, oldProtect, &newProtect)) {
#if _DEBUG
							printf("[!] VirtualProtectEx failed restoring permissions after unhook/re-hook!%d\n");
#endif
						}
						return FALSE;
					}
				}
			}
		}
	}
	// change the memory permissions back to their original value
	if (!VirtualProtectEx(targetModule->hProcess, start, numberOfBytes, oldProtect, &newProtect)) {
#if _DEBUG
		printf("[!] VirtualProtectEx failed restoring permissions after unhook/re-hook!%d\n");
#endif
		return FALSE;
	}

	return TRUE;
}

/*
Returns TRUE if all modified RVAs for a given function are consecutive
*/
BOOL isConsecutiveRVAs(hookedFunction* function, PDWORD modifiedRVAs) {
	DWORD prev, current;

	// get the first modified RVA for our function
	prev = modifiedRVAs[function->modifiedRVAsIndexes[0]];

	// note i = 1 
	for (WORD i = 1; i < function->modifiedRVAsIndexesCount; i++) {
		
		current = modifiedRVAs[function->modifiedRVAsIndexes[i]];
		// if previous + 1 is not equal to the current - then not all RVAs are consecutive
		if (prev + 1 != current)
			return FALSE;
		else
			prev = current;
	}

	return TRUE;
}

// unused functions make if planning to use, include the header below
//#include <Stringapiset.h> // for UTF16 to UTF8 conversation

//LPVOID findFunctionOffset(mineSweeperModuleInfo* targetModule, wchar_t* functionName) {
//	
//	// convert to utf8 string in order to call GetProcAddress which accepts only ASCI
//	char* utf8FunctionName = utf16toUtf8(functionName);
//
//	// get target function memory address
//	FARPROC pFunction = GetProcAddress(targetModule->hModule, utf8FunctionName);
//	
//	// calculate the function offset from the module's base address
//	LPVOID functionOffset = (unsigned int)pFunction - (unsigned int)targetModule->moduleBaseAddress;
//
//#if _DEBUG
//	printf("Address of %ls: %#X\n", functionName, &pFunction);
//	printf("Offset: %#X", functionOffset);
//#endif
//
//	// free the utf8 string that we created with malloc
//	free(utf8FunctionName);
//
//	return functionOffset;
//}
//

//// CAUTION: make sure to free the utf8Sttring memory after calling this function
//char* utf16toUtf8(wchar_t* utf16String) {
//	// get the required size of the resulting utf8 string
//	int size = WideCharToMultiByte(CP_UTF8, 0, utf16String, -1, NULL, 0, 0, NULL);
//	
//	// allocate memory for our utf8 string
//	char * utf8String = malloc(size * sizeof(char));
//
//	// convert utf16 string to utf8 and write the result into our allocated memory
//	WideCharToMultiByte(CP_UTF8, 0, utf16String, -1, utf8String, size, 0, NULL);
//
//	return utf8String;
//}

