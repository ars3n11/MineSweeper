# MineSweeper

Windows user-land hooks manipulation tool.

## Highlights

- Supports any x64/x86 Windows DLL (actually, any x64/x86 Windows PE for that matter)
- 4 main features
    - Enumerates loaded modules in the target process (`-l` flag) 
    - Finds user-land hooks in loaded modules (`-s` flag) 
    - Unhooks specified modules (`-u` flag)
    - Re-hooks specified modules (`-r` flag)
- Shows which function RVAs have been modified with byte-to-byte comparison (`-v` flag)
- Cross-architecture support for the x64 variant.
- Cautious mode: can unhook itself first before manipulating remote processes (`-c` flag)
- Can target either all loaded modules within the target process or only those containing a specified string in their path (`-m` flag)
- Lightweight: x64 and x86 binaries are only 18KB and 17KB respectively.
- No Visual C++ Redistributable Packages (`vcruntime140.dll`) dependency. MineSweeper dynamically links to the following Windows core libraries present on every modern distribution: `msvcrt.dll` and `kernel32.dll`.

## Command Line Reference

```
MineSweeper by @ars3n11
Usage:  MineSweeper.exe  [-c] [-l | -s | -u  | -r] [-t targetPID] [-v]
                        [-m moduleNameStringMatch] [-d hookDonorPID]
Modes available:
        -l      List Mode - List loaded modules by the target process (-t).
                Module name filter (-m) is available.
        -s      Sweep Mode - Sweep target PID (-t) for any user-land hooks.
                Module name filter (-m) is available.
        -u      Unhook Mode - Sweep and unhook target PID (-t) from any user-land hooks.
                Module name filter (-m) is available.
        -r      Re-hook Mode - Sweep hook donor PID (-d) for user-land hooks.
                If any hooks found - copy them over to our target PID (-t).
                Module name filter (-m) is available.
Safety modes:
        -c      Cautious Mode - Unhook the local process before proceeding with
                one of the chosen main modes.
Options:
        -t      Target PID. Will target the local process if not provided.
        -d      Hook donor PID (i.e.: the process that will be used to copy hooks FROM).
                Will set the local process as the hooks donor if not provided.
        -m      Filter string to be applied to the loaded module canonical path
                (e.g: \Device\HarddiskVolume3\Windows\System32\ntdll.dll).
                Will target all modules (same as "-m .dll") if not provided.
        -v      Verbose flag. Prints modified RVAs and their byte-to-byte comparison for each hooked function.
Examples:
MineSweeper.exe: -l             List loaded modules in MineSweeper's own process.
MineSweeper.exe: -l -t 5476     List loaded modules in PID 5476.
MineSweeper.exe: -s             Sweep MineSweeper's local process for user-land hooks.
MineSweeper.exe: -s -v          Same as above but also print modified RVAs for each hooked function.
MineSweeper.exe: -s -t 5476     Sweep PID 5476 for user-land hooks.
MineSweeper.exe: -u -t 5476     Unhook PID 5476 from all user-land hooks.
MineSweeper.exe: -c -u -t 5476  Unhook PID 5476 from all user-land hooks. Run in Cautious mode (unhook
                                MineSweeper's own process before trying to unhook PID 5476).
MineSweeper.exe: -u -t 5476 -m ntdll.dll        Unhook PID 5476 from any hooks found in the ntdll.dll module.
MineSweeper.exe: -r -t 5476 -d 8156     Sweep PID 8156 for user-land hooks and copy over any discovered
                                        hooks into the matching modules in the PID 5476.
MineSweeper.exe: -c -r -t 5476 -d 8156  Same as above but run in Cautious mode (unhook MineSweeper's
                                        own process before doing anything else).
```

## Cross-architecture

x64 version of MineSweeper can enumerate and manipulate both x64 and x86 processes. This only applies to the x64 version since a call to `EnumProcessModulesEx` function from an x86 process will return x86 module handles only.

Cross-architecture support:
|     | x86 | x64 |
|-----|-----|-----|
| **x86** | Yes | No  |
| **x64** | Yes | Yes |


## Dependencies

> TLDR: nothing to worry about, you can clone the repo and go straight to [compiling](#Compiling).

- Imports a total of 28 functions from `msvcrt.dll` and `kernel32.dll`.
- Links to `msvcrt.dll` to avoid Visual C++ Redistributable Packages (`vcruntime140.dll`) dependency.

### Linking to `msvcrt.dll`

I wanted to link MineSweeper to `msvcrt.dll` in order to avoid `C++ Redistributable Packages` dependency for C runtime. I first looked at [Benjamin Delpi's](https://twitter.com/gentilkiwi) approach [used in Mimikatz](https://blog.gentilkiwi.com/programmation/executables-runtime-defaut-systeme). That looked too complex for the task at hand and after a few more nights of research I came across [Mahmoud Al-Qudsi's](https://twitter.com/mqudsi) elegant [msvcrt.lib project](https://github.com/neosmart/msvcrt.lib) which is what we are using here.

For convenience, I included the `msvcrt.lib` files in this project already so you don't need to pull them twice. They are located under `libs/msvcrt/`.

## Compiling

Download compiled binaries [here](https://github.com/ars3n11/MineSweeper/releases/). 

Since opening 3rd party Visual Studio project files is _mauvais ton_ these days, I'm providing command line compilation instructions below. The VS project files are also included in the repo, so that's always an option too.

### Compiling in CLI

Step 1: Compile (make sure to use the right `cl.exe` for your target architecture!).

```
cl.exe /GS- /GL /W4 /O1 /nologo /Zl /Os /Oi /c /D "_UNICODE" /D "UNICODE" MineSweeper.c MineSweeperCore.c
```

Step 2: Link - x64:

```
link.exe /LTCG /ENTRY:"wmain_custom" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /NODEFAULTLIB /MACHINE:X64 /OUT:"MineSweeper_cmd_compiled.exe" MineSweeper.obj MineSweeperCore.obj  libs\msvcrt\x64\msvcrt.lib kernel32.lib
```
OR

Step 2: Link - x86:

```
link.exe /LTCG /ENTRY:"wmain_custom" /OPT:REF /SAFESEH:NO /SUBSYSTEM:CONSOLE /NODEFAULTLIB /MACHINE:x86 /OUT:"MineSweeper_cmd_compiled.exe" MineSweeper.obj MineSweeperCore.obj libs\msvcrt\x86\msvcrt.lib kernel32.lib
```

## Exceptions

There are several use cases where MineSweeper will not be able to sweep a specified process module. Whenever it encounters the below listed conditions, MineSweeper will notify the user in `stdout` and skip the module.

- A DLL without a `.text` section (e.g.: `FileSync.Resources.dll` and `FileSync.LocalizedResources.dll` loaded by `OneDrive.exe`).
- Non-consecutively committed PE sections. The only example I have observed during my testing was `kernel32.dll` in a x86 process running on a x64 system where. The committed memory regions had reserved memory regions in between them preventing `ReadProcessMemory` function from reading the target module all at once.
- Modules with large chunks of `.text` section being overwritten. In my testing I have come across several instances where random parts of a module's `.text` section were overwritten resulting in a false positive. I was not able to explain this behavior since it was sporadic and affected different modules each time. Normally, a hooked module would have less than 1% of its `.text` section modified so that is what MineSweeper is checking for to avoid this condition.

## How it Works

Below is a high-level overview of the unhooking (`-u` flag) workflow which also invokes module enumeration (`-l` flag) and sweeping for hooks (`-s` flag) functions. 

1. Enumerate target process modules via `EnumProcessModulesEx` function.
1. Identify modules of interest by their file name / path.
1. [If targeting a remote process] Copy over the remote process module to our local process using `ReadProcessMemory`.
1. Map view of file of the module of interest on disk using `CreateFileMapping` (`PAGE_READONLY | SEC_IMAGE_NO_EXECUTE`) and `MapViewOfFile`
1. Byte-to-byte comparison of the `.text` section of the dll saved on disk against the dll module loaded by the target process in memory. During this process, MineSweeper takes a note of the original values currently present in the dll on disk as well as the modified values identified in memory.
1. [For the `-l` flag only] Cross-reference `.text` section differences to specific function ordinals in the PE EAT (portable executable export address table).
1. Modify remote process target module memory permissions to `PAGE_EXECUTE_READWRITE` using `VirtualProtectEx` in order to overwrite the hooks.
1. Overwrite the hooks in the target module using `WriteProcessMemory` for a remote process or simply dereferencing the memory pointer for a local process (in order to avoid `WriteProcessMemory` call).
1. Modify the memory permissions back to the original ones using `VirtualProtectEx`.

## OpSec Considerations

MineSweeper currently possesses very limited set of evasion techniques. The primary goal of the project was to do required heavy-lifting for hook detection across as many DLLs as possible on a modern Windows system.

Nonetheless, in my testing it was working fine (enumerating hooks and unhooking remote process modules) on systems with cutting-edge enterprise EDRs. This was true so long the MineSweeper's Cautious mode (`-c` flag) was on.

Below is a short list of MineSweeper's opsec features:

- The Cautious mode (`-c` flag) will unhook MineSweeper's own process first before attempting to manipulate a remote process.
- Creating on-disk file mapping is done with `PAGE_READONLY | SEC_IMAGE_NO_EXECUTE` permissions in order "to avoid triggering multiple image load events". Shout out to [@slaeryan](https://twitter.com/slaeryan) for the [tip](https://twitter.com/slaeryan/status/1336959057232449536).
- Overwriting local process hooks is done by memory address pointer dereference to avoid calling `WriteProcessMemory` function.


## Use Cases

While this project was initially conceived as a learning opportunity for Windows API, C and PE format, there are a couple opportunities for a practical application of the project:

- For Blue Team to test their tooling and telemetry against various user-land unhooking techniques.
- For Red Team for situational awareness on a target system.

## Troubleshooting

- If a target process crashes after unhooking or re-hooking, try enabling Cautious mode (`-c` flag). 

## Demo
![MineSweeper Demo](https://user-images.githubusercontent.com/41267859/114948584-47285d80-9e1d-11eb-8d47-b3e5c7aedd4c.gif)