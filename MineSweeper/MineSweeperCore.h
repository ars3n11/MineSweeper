#pragma once
#include <Windows.h>
#include <Libloaderapi.h>
#include <Processthreadsapi.h>
#include <Psapi.h>
#include <Memoryapi.h> // for memory query and manipulation.
#include <WINNT.h> // for PE header data structures
#define filePathLength 200 // max fully qualified path for the file name of the target DLL
#define UNHOOK 0
#define REHOOK 1
#define LIST_MODE L'l' // list target proceess modules
#define SWEEP_MODE L's' // sweep targeet process for hooks
#define UNHOOK_MODE L'u' // unhook target process
#define REHOOK_MODE L'r' // rehook target process with hooks from donor
#define CAUTIOUS_MODE L'c' // unhook our own process before executing any other command


// declare a struct for our linked list to keep track of the hooked RVAs
typedef struct modifiredRVAListNodeStruct {
	DWORD rva; // RVA relative to the image base
	struct modifiredRVAListNodeStruct* next;
}modifiedRVAListNode;

// a struct to keep a list of hookend functions names, EAT / EOT ordinals and their RVAs
typedef struct hookedFunctionStruct {
	char* functionName; // pointers to the Export Name Pointer Table
	WORD eotOrdinal; // unbiased function ordinal 
	WORD eatOrdinal; // function ordinal in the EAT
	PWORD modifiedRVAsIndexes; // indexes of modifiedRVAs array which is a part of mineSweeperModuleInfo struct
	WORD modifiedRVAsIndexesCount;
} hookedFunction;


// the struct to keep all the target module info
typedef struct mineSweeperModuleInfo {
	HMODULE hModule;
	HANDLE hProcess;
	DWORD_PTR moduleBase; //same as hModule if it's a local process module otherwise it's a base address of the local copy of the remote's process module
	HANDLE hTargetDllOnDisk;
	HANDLE hTargetDllOnDiskFileMapping;
	LPVOID hTargetDllOnDiskMappingAddress;
	wchar_t * filePath;
	wchar_t* moduleName;
	PIMAGE_EXPORT_DIRECTORY edt; // export directory table
	PDWORD eat; // Export Address Table
	PDWORD npt; // Name Pointer Table
	PWORD eot; // Export Ordinal Table
	PDWORD modifiedRVAs; // an array that contains RVAs that have been modified
	DWORD modifiedRVAsLength;
	BYTE* hookedRVAValues; // actual values of the modified RVAs - length of the array equals to modifiedRVAsLength
	BYTE* unhookedRVAValues; // actual values of the unmodified (i.e. unhooked) RVAs  - length of the array equals to modifiedRVAsLength
	hookedFunction * hookedFunctions; // struct for the unique hooked functions (multiple modified RVAs may be part of the same function)
	DWORD hookedFunctionsLength;
} mineSweeperModuleInfo;

BOOL mapFileFromDisk(mineSweeperModuleInfo* targetModule);
VOID cleanUpModule(mineSweeperModuleInfo* targetModule);
PIMAGE_EXPORT_DIRECTORY getExportDirectoryTable(HMODULE module);
char* EOTIndexToFuncName(HMODULE module, DWORD ordinal);
PDWORD getExportAddressTable(HMODULE module);
PWORD getExportOrdinalTable(HMODULE module);
PIMAGE_SECTION_HEADER getTextSection(HMODULE module);
int memcmpCustom(const void* s1, const void* s2, size_t n, size_t start);
int findClosestEAT_RVA(DWORD_PTR targetByte, DWORD_PTR moduleBase, PDWORD eat, size_t eat_length);
PDWORD getNamePointerTable(HMODULE module);
int EATIndexToEOTIndex(WORD eatIndex, PWORD eot, DWORD eotLength);
BOOL sweepModule(mineSweeperModuleInfo* moduleInfo);
DWORD getModifiedRVAListLength(modifiedRVAListNode* head);
void cleanModifiedRVAList(modifiedRVAListNode* head);
BOOL moveModifiedRVAListToArray(modifiedRVAListNode* head, PDWORD array, DWORD arrayLength);
mineSweeperModuleInfo* initializeMineSweeperModuleInfo(HMODULE moduleHandle, HANDLE hProcess);
DWORD buildHookedFunctionsArray(mineSweeperModuleInfo * targetModule);
char* EOTIndexToFuncNameMineSweeper(mineSweeperModuleInfo* targetModule, DWORD ordinal);
void printHookedFunctions(mineSweeperModuleInfo* targetModule);
DWORD_PTR readRemoteModule(HMODULE hModule, HANDLE hProcess);
wchar_t* getModuleFilePath(HMODULE hModule, HANDLE hProcess);
BOOL getProcessModules(HANDLE hProcess, HMODULE** modules, DWORD* modulesLength);
void printProcessModules(HANDLE hProcess, HMODULE* modules, DWORD modulesLength);
BOOL findModuleHandleByFilePath(HANDLE hProcess, HMODULE* modules, DWORD modulesLength, HMODULE** matchedModules, DWORD* matchedModulesLength, wchar_t* searchString);
BOOL sweepProcessModules(DWORD pid, wchar_t* moduleName);
BOOL listProcessModules(DWORD pid, wchar_t* moduleName);
BOOL isConsecutiveRVAs(hookedFunction* function, PDWORD modifiedRVAs);
BOOL unhookOrRehookModule(mineSweeperModuleInfo* targetModule, BYTE mode);
BOOL unhookProcessModules(DWORD pid, wchar_t* moduleName);
BOOL rehookProcessModules(DWORD pid, wchar_t* moduleName, DWORD hookedPID);
BOOL isTextSectionOverwritten(mineSweeperModuleInfo* targetModule);