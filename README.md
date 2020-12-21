# KernelBhop

~Updated added a Module Search for Module Base address and Module Size based on DLL name.

Cheat that uses a driver instead WinAPI for Reading / Writing memory. 

* TODO: `AOB Scan (Array of bytes)` still isn't ported over to the driver, it will call detected Kernel32.dll Memory reading which will crash the cheat or get you detected.

Unsigned Drivers can be loaded using https://github.com/hfiref0x/DSEFix

This project uses a kernel mode driver in co-operation with a user mode program to establish a method of reading / writing virtual memory from a regular win32 program without having to use regular WinAPI Functions. This happens by using a driver to execute the reading / writing of the memory itself from a lower level. This means the user mode program does not have to open any handles to csgo or use ReadProcessMemory or WriteProcessMemory nor any functions that has to deal with process handles.

VAC’s defence against external cheats is based on system handle scanning on user level. VAC scans handles in the system (ring3), when it finds a handle which for example points to cs:go, the process that holds that handle will be analysed.

This can be avoided by not opening any handles to csgo (OpenProcess()), but it also means we can’t use any WinAPI Functions to Read/Write the memory of the process that we want, so we must go to a lower level. As of now, VAC or valve does not have any drivers which means if we can write & get kernel code running defeating vac is possible.

“Then a scanning thread is created. This thread repeatedly scans all handles in the system (calls NtQuerySystemInformation with SystemHandleInformation information class) for handles to the process its running from and logs any process holding it into the first section object. VAC uses NtQueryInformationProcess with ProcessImageFileName information class to find the image name of the process, tries to open it with NtCreateFile and uses GetFileInformationByHandle to get the volume serial number and the file identifier (it won't change if you rename or move the file).”

Methods with KeInterface:

* `SetTargetProcessName(string *target)`
Set new target game exe image name to driver. You can sign driver once and make it work with most of games.

* `GetTargetPid()`
Get pid of the Image you want to RPM/WPM with. Return DWORD64.

* `GetClientBaseAddressModule()`
Get target process' base address. Return 16-bytes address instead of 8-bytes address in Zer0Mem0ry's driver for X64. You can simply convert it to DWORD make it compatible with X86.

* `ReadVirtualMemory<type>(ULONG64 ProcessId, ULONG64 ReadAddress, SIZE_T Size)`
Read max to 16 bytes from ReadAddress, and convert to type.

* `ReadString(ULONG64 ProcessId, ULONG64 ReadAddress, SIZE_T Size)`
Read max to X bytes from ReadAddress, and convert to std::string.

* `BOOLEAN IsValidAddress(ULONG ReadAddress)`
Check if address is valid or bad, doesn't require processID, which is strange but whatever :D.

* `WriteVirtualMemory(ULONG64 ProcessId, ULONG64 WriteAddress, ULONG WriteValue, SIZE_T WriteSize)`
Write max to 8 bytes to WriteAddress.

* `WriteVirtualMemory64(ULONG64 ProcessId, ULONG64 WriteAddress, ULONG64 WriteValue, SIZE_T WriteSize)`
Write max to 16 bytes to WriteAddress. If you want to write float or something others to memory, use reinterpret_cast or just use it as what i do in Ring3console.

* `DWORD GetModulesInformation(MEMORY_REQUEST* moduleList)`
Get Module information for whatever .dll you are trying to get Base Address / Module Size.

* `DWORD VirtualQueryInfo(VIRTUAL_QUERY_REQUEST* moduleList)`
Get Safe Readable/Writable values for whatever address region you are checking.

https://www.unknowncheats.me/wiki/Valve_Anti-Cheat:VAC_external_tool_detection_(and_more)
