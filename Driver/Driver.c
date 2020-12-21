/* Cheat that uses a driver for reading / writing virtual memory,
instead of using Win32API Functions. Written By Zer0Mem0ry,
https://www.youtube.com/watch?v=sJdBtPosWQs */

#include "ntos.h"

const WCHAR deviceNameBuffer[] = L"\\Device\\kernelhop";
const WCHAR deviceSymLinkBuffer[] = L"\\DosDevices\\kernelhop";

// type definitions
typedef unsigned long long QWORD;
typedef unsigned short WORD;
typedef unsigned long DWORD, * PDWORD, * LPDWORD;
typedef unsigned char BYTE, *PBYTE;

// Request to read virtual user memory (memory of a program) from kernel space
#define IO_READ_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0700 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to write virtual user memory (memory of a program) from kernel space
#define IO_WRITE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0701 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to check if is valid address
#define IO_IS_VALID_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0702 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to retrieve the process id of csgo process, from kernel space
#define IO_SET_PROCESS_NAME_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0703 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to retrieve the module base/size of process, from kernel space
#define IO_GET_MODULE_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0704 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to retrieve the module base/size of process, from kernel space
#define IO_VIRTUAL_QUERY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0705 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request virtual memory protection on address/size from kernel space
#define IO_PROTECT_VIRTUAL_MEMORY_REQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0706 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

// Request to retrieve the base address of client.dll in csgo.exe from kernel space
#define IO_GET_BASE_ADDRESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x0707 /* Our Custom Code */, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

PDEVICE_OBJECT pDeviceObject; // our driver object

UNICODE_STRING dev, dos; // Driver registry paths

ULONG GameProcessId, GameBaseAddress;

#if defined(_X86_)
#define ProbeForReadUnicodeStringFullBuffer(String)                                                          \
    if (((ULONG_PTR)((String).Buffer) & (sizeof(BYTE) - 1)) != 0) {                                   \
        ExRaiseDatatypeMisalignment();                                                            \
    } else if ((((ULONG_PTR)((String).Buffer) + ((String).MaximumLength)) < (ULONG_PTR)((String).Buffer)) ||     \
               (((ULONG_PTR)((String).Buffer) + ((String).MaximumLength)) > (ULONG_PTR)MM_USER_PROBE_ADDRESS)) { \
        ExRaiseAccessViolation();                                                                 \
    } else if (((String).Length) > ((String).MaximumLength)) {                                    \
        ExRaiseAccessViolation();                                                                 \
    }
#else
#define ProbeForReadUnicodeStringFullBuffer(String)                                                        \
    if (((ULONG_PTR)((String).Buffer) & (sizeof(WCHAR) - 1)) != 0) {                                  \
        ExRaiseDatatypeMisalignment();                                                            \
    } else if ((((ULONG_PTR)((String).Buffer) + ((String).MaximumLength)) < (ULONG_PTR)((String).Buffer)) ||     \
               (((ULONG_PTR)((String).Buffer) + ((String).MaximumLength)) > (ULONG_PTR)MM_USER_PROBE_ADDRESS)) { \
        ExRaiseAccessViolation();                                                                 \
    } else if (((String).Length) > ((String).MaximumLength)) {                                    \
        ExRaiseAccessViolation();                                                                 \
    }
#endif

// datatype for read request
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY64	InLoadOrderLinks;
	LIST_ENTRY64	InMemoryOrderLinks;
	LIST_ENTRY64	InInitializationOrderLinks;
	UINT64			DllBase;
	UINT64			EntryPoint;
	ULONG			SizeOfImage;
	UNICODE_STRING	FullDllName;
	UNICODE_STRING 	BaseDllName;
	ULONG			Flags;
	USHORT			LoadCount;
	USHORT			TlsIndex;
	PVOID			SectionPointer;
	ULONG			CheckSum;
	PVOID			LoadedImports;
	PVOID			EntryPointActivationContext;
	PVOID			PatchInformation;
	LIST_ENTRY64	ForwarderLinks;
	LIST_ENTRY64	ServiceTagLinks;
	LIST_ENTRY64	StaticLinks;
	PVOID			ContextInformation;
	ULONG64			OriginalBase;
	LARGE_INTEGER	LoadTime;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// structure definitions
typedef struct _MODULE_INFO
{
	UINT64 Base;
	ULONG Size;
	WCHAR Name[1024];
} MODULE_INFO, *PMODULE_INFO;

typedef struct _KERNEL_READ_REQUEST
{
	UINT64 Address; // Source
	SIZE_T Size;
	PVOID Response; // Target
} KERNEL_READ_REQUEST, *PKERNEL_READ_REQUEST;

typedef struct _KERNEL_WRITE_REQUEST
{
	UINT64 Address; // Target
	PVOID Value; // Source
	SIZE_T Size;
	BOOLEAN BytePatching;
} KERNEL_WRITE_REQUEST, *PKERNEL_WRITE_REQUEST;

typedef struct _KERNEL_MODULE_REQUEST
{
	MODULE_INFO buffer;
	WCHAR moduleName[1024];
} KERNEL_MODULE_REQUEST, *PKERNEL_MODULE_REQUEST;

typedef struct _MEMORY_REQUEST
{
	ULONG ProcessId;
	KERNEL_READ_REQUEST read;
	KERNEL_WRITE_REQUEST write;
	KERNEL_MODULE_REQUEST module;
} MEMORY_REQUEST, *PMEMORY_REQUEST;

typedef struct _VIRTUAL_QUERY_REQUEST
{
	ULONG ProcessId;
	UINT64 Address; // Target
	MEMORY_BASIC_INFORMATION info;
} VIRTUAL_QUERY_REQUEST, *PVIRTUAL_QUERY_REQUEST;

typedef struct _PROTECT_VIRTUAL_MEMORY_REQUEST
{
	ULONG ProcessId;
	UINT64 Address; // Target
	DWORD size;
	ULONG NewAccessProtection;
	ULONG OldAccessProtection;
} PROTECT_VIRTUAL_MEMORY_REQUEST, *PPROTECT_VIRTUAL_MEMORY_REQUEST;

typedef struct _GET_PROCESS_ID_REQUEST
{
	ULONG ProcessId;
	wchar_t processName[256];
} GET_PROCESS_ID_REQUEST, *PGET_PROCESS_ID_REQUEST;

// method definitions
DWORD PEBLDR_OFFSET = 0x18; // peb.ldr
DWORD PEBLDR_MEMORYLOADED_OFFSET = 0x10; // peb.ldr.InMemoryOrderModuleList

NTKERNELAPI PVOID PsGetProcessSectionBaseAddress(__in PEPROCESS Process);

NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject);
NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp);
NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp);

NTSTATUS SearchProcessModules(MEMORY_REQUEST* sent) {
	PEPROCESS Process;
	KAPC_STATE APC;
	NTSTATUS Status = STATUS_FAIL_CHECK;

	PVOID processId = (PVOID)sent->ProcessId;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	PMODULE_INFO ModuleList = ExAllocatePool(PagedPool, sizeof(MODULE_INFO) * 512);
	if (ModuleList == NULL)
		return STATUS_MEMORY_NOT_ALLOCATED;

	RtlZeroMemory(ModuleList, sizeof(MODULE_INFO) * 512);

	PPEB Peb = PsGetProcessPeb(Process);
	if (!Peb)
		return STATUS_INVALID_PARAMETER_1;

	__try {
		KeStackAttachProcess(Process, &APC);

		UINT64 Ldr = (UINT64)Peb + PEBLDR_OFFSET;
		ProbeForRead((CONST PVOID)Ldr, 8, 8);

		PLIST_ENTRY ModListHead = (PLIST_ENTRY)(*(PULONG64)Ldr + PEBLDR_MEMORYLOADED_OFFSET);
		ProbeForRead((CONST PVOID)ModListHead, 8, 8);

		PLIST_ENTRY Module = ModListHead->Flink;

		DWORD index = 0;
		while (ModListHead != Module) {
			LDR_DATA_TABLE_ENTRY* Module_Ldr = (LDR_DATA_TABLE_ENTRY*)(Module);

			ModuleList[index].Base = Module_Ldr->DllBase;
			ModuleList[index].Size = Module_Ldr->SizeOfImage;
			RtlCopyMemory(ModuleList[index].Name, Module_Ldr->BaseDllName.Buffer, Module_Ldr->BaseDllName.Length);

			Module = Module->Flink;
			index++;
		}

		KeUnstackDetachProcess(&APC);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		KeUnstackDetachProcess(&APC);
	}

	ModuleList[0].Base += (UINT64)PsGetProcessSectionBaseAddress(Process);

	WCHAR ModuleName[1024];

	RtlZeroMemory(ModuleName, 1024);
	wcsncpy(ModuleName, sent->module.moduleName, 1024);

	MODULE_INFO SelectedModule;
	for (DWORD i = 0; i < 512; i++) {
		MODULE_INFO CurrentModule = ModuleList[i];

		if (_wcsicmp(CurrentModule.Name, ModuleName) == 0) {
			SelectedModule = CurrentModule;
			break;
		}
	}

	if (SelectedModule.Base != NULL && SelectedModule.Size != NULL) {
		sent->module.buffer = SelectedModule;
	}

	ExFreePool(ModuleList);
	ObfDereferenceObject(Process);

	return Status;
}

SIZE_T FindProcessByName(wchar_t* name) {

	ULONG bufferSize = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemProcessInformation, NULL, bufferSize, &bufferSize);

	if (!bufferSize)
		return NULL;

	PVOID memory = ExAllocatePoolWithTag(PagedPool, bufferSize, 'enoN');

	if (bufferSize > 409600) {
		DbgPrint("Error space needed to find process by name\n");
		return NULL;
	}

	status = ZwQuerySystemInformation(SystemProcessInformation, memory, bufferSize, &bufferSize);
	if (!NT_SUCCESS(status))
	{
		ExFreePool(memory);
		return 0;
	}

	PSYSTEM_PROCESSES pProcess = (PSYSTEM_PROCESSES)memory;

	//DbgPrint("Searching for %ws\n", name);
	int sizeOfName = wcslen(name);
	while (TRUE)
	{
		pProcess = (PSYSTEM_PROCESSES)((BYTE*)pProcess + pProcess->NextEntryDelta);

		__try {
			if (&pProcess->ProcessName != NULL) {
				if (memcmp(pProcess->ProcessName.Buffer, name, sizeOfName * 2) == 0) {
					DbgPrint("New Process Set [name: %wZ]  - [Process ID: %d]\n", pProcess->ProcessName, pProcess->ProcessId);
					ExFreePool(memory);
					return pProcess->ProcessId;
				}
			}
		} 
		__except (EXCEPTION_EXECUTE_HANDLER) 
		{ 
	        	DbgPrintEx(0, 0, "Error FindProcessByName UNICODE_STRING code: %X\n", GetExceptionCode());
		}

		if (pProcess->NextEntryDelta == 0)
			break;
	}
	ExFreePool(memory);
	return 0;
}

NTSTATUS RVM(ULONG PID, MEMORY_REQUEST* sent) {
	PEPROCESS Process;

	// lookup eprocess for use in attaching
	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	// create our own variables for usermode buffer, for some reason it will crash if we dont use these variables
	PVOID Address = (PVOID)sent->read.Address;
	SIZE_T Size = sent->read.Size;

	// alocate memory for our driverbuffer, will be used to read memory from the process
	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	if (Buffer == NULL) {
		ObfDereferenceObject(Process);

		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlSecureZeroMemory(Buffer, Size);

	KAPC_STATE APC;
	NTSTATUS Status = STATUS_FAIL_CHECK;

	__try {
		// attach
		KeStackAttachProcess(Process, &APC);

		// query information on memory to verify it meets our requirements
		MEMORY_BASIC_INFORMATION info;
		if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_INVALID_ADDRESS_COMPONENT;

			return Status;
		}

		ULONG flags = PAGE_EXECUTE_READWRITE | PAGE_READWRITE | PAGE_EXECUTE_READ;
		ULONG page = PAGE_GUARD | PAGE_NOACCESS;

		// confirm memory block meets our requirements
		if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		// secure memory so it doesnt change between the beginning of the request & the end, practically the same as doing ZwProtectVirtualMemory
		HANDLE Secure = MmSecureVirtualMemory(Address, Size, PAGE_READWRITE);
		if (Secure == NULL) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_VIOLATION;

			return Status;
		}

		if (MmIsAddressValid(Address) == FALSE) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_VIOLATION;

			return Status;
		}

		// read memory to our driver's buffer
		memcpy(Buffer, Address, Size);

		// cleanup, unsecure memory & detach from process
		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		// read memory from our driver's buffer over to our usermode buffer
		memcpy(sent->read.Response, Buffer, Size);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// detach if anything goes wrong
		KeUnstackDetachProcess(&APC);
	}

	// cleanup for us, deallocate buffer memory & deref eprocess as we added a ref
	ExFreePool(Buffer);
	ObfDereferenceObject(Process);

	return Status;
}

NTSTATUS WVM(ULONG PID, MEMORY_REQUEST* sent) {
	PEPROCESS Process;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	PVOID Address = (PVOID)sent->write.Address;
	SIZE_T Size = sent->write.Size;

	// allocate memory for our driver buffer
	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	if (Buffer == NULL) {
		ObfDereferenceObject(Process);

		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlSecureZeroMemory(Buffer, Size);

	KAPC_STATE APC;
	NTSTATUS Status = STATUS_FAIL_CHECK;

	__try {
		// copy our usermode buffer's value over to our driver's buffer
		memcpy(Buffer, sent->write.Value, Size);

		KeStackAttachProcess(Process, &APC);

		MEMORY_BASIC_INFORMATION info;
		if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_INVALID_PARAMETER_2;

			return Status;
		}

		ULONG flags = PAGE_EXECUTE_READWRITE | PAGE_READWRITE;
		ULONG page = PAGE_GUARD | PAGE_NOACCESS;

		if (!(info.State & MEM_COMMIT) || !(info.Protect & flags) || (info.Protect & page)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		HANDLE Secure = MmSecureVirtualMemory(Address, Size, PAGE_READWRITE);
		if (Secure == NULL) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_VIOLATION;

			return Status;
		}

		if (MmIsAddressValid(Address) == FALSE) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_VIOLATION;

			return Status;
		}

		// send our driver's buffer to our applications memory address
		memcpy(Address, Buffer, Size);

		MmUnsecureVirtualMemory(Secure);
		KeUnstackDetachProcess(&APC);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&APC);
	}

	ExFreePool(Buffer);
	ObfDereferenceObject(Process);

	return Status;
}

NTSTATUS WVMP(ULONG PID, MEMORY_REQUEST* sent) { // write virtual memory, with less restrictions, should only be used for byte patching in protected memory regions
	PEPROCESS Process;
	KAPC_STATE APC;
	NTSTATUS Status;

	if (!NT_SUCCESS(PsLookupProcessByProcessId((PVOID)PID, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	PVOID Address = (PVOID)sent->write.Address;
	PVOID ProtectedAddress = (PVOID)sent->write.Address;
	SIZE_T Size = sent->write.Size;
	SIZE_T ProtectedSize = sent->write.Size;

	PVOID* Buffer = (PVOID*)ExAllocatePool(NonPagedPool, Size); // Pointer to Allocated Memory
	if (Buffer == NULL) {
		ObfDereferenceObject(Process);

		return STATUS_MEMORY_NOT_ALLOCATED;
	}

	RtlSecureZeroMemory(Buffer, Size);

	__try {
		memcpy(Buffer, sent->write.Value, Size);

		KeStackAttachProcess(Process, &APC);

		ULONG OldProtection;
		Status = ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, PAGE_EXECUTE_READWRITE, &OldProtection);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			return Status;
		}

		ProtectedAddress = Address;
		ProtectedSize = Size;

		MEMORY_BASIC_INFORMATION info;
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			return Status;
		}

		if (!(info.State & MEM_COMMIT)) {
			ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, OldProtection, &OldProtection);
			KeUnstackDetachProcess(&APC);

			ExFreePool(Buffer);
			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		memcpy(Address, Buffer, Size);

		ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, OldProtection, &OldProtection);
		KeUnstackDetachProcess(&APC);

		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&APC);
	}

	ExFreePool(Buffer);
	ObfDereferenceObject(Process);

	return Status;
}

NTSTATUS VirtualQueryInfo(VIRTUAL_QUERY_REQUEST* sent) {
	PEPROCESS Process;
	PVOID processId = (PVOID)sent->ProcessId;

	// lookup eprocess for use in attaching
	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	// create our own variables for usermode buffer, for some reason it will crash if we dont use these variables
	PVOID Address = (PVOID)sent->Address;
	KAPC_STATE APC;
	NTSTATUS Status = STATUS_FAIL_CHECK;

	__try {
		// attach
		KeStackAttachProcess(Process, &APC);

		// query information on memory to verify it meets our requirements
		if (!NT_SUCCESS(ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &sent->info, sizeof(MEMORY_BASIC_INFORMATION), NULL))) {
			KeUnstackDetachProcess(&APC);

			ObfDereferenceObject(Process);
			Status = STATUS_INVALID_ADDRESS_COMPONENT;
			return Status;
		}
		KeUnstackDetachProcess(&APC);
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		// detach if anything goes wrong
		KeUnstackDetachProcess(&APC);
	}

	// cleanup for us, deref eprocess as we added a ref
	ObfDereferenceObject(Process);
	return Status;
}

NTSTATUS ForceProtectVirtualMemory(PROTECT_VIRTUAL_MEMORY_REQUEST* sent) {
	// write virtual memory protection, with less restrictions, should only be used for byte patching in protected memory regions
	PEPROCESS Process;
	PVOID processId = (PVOID)sent->ProcessId;
	KAPC_STATE APC;
	NTSTATUS Status = STATUS_FAIL_CHECK;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(processId, &Process)))
		return STATUS_INVALID_PARAMETER_1;

	PVOID Address = (PVOID)sent->Address;
	PVOID ProtectedAddress = (PVOID)sent->Address;
	SIZE_T Size = sent->size;
	SIZE_T ProtectedSize = sent->size;
	ULONG NewProtect = sent->NewAccessProtection;

	__try {
		//attach
		KeStackAttachProcess(Process, &APC);

		//Status = ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, NewProtect, OldProtection);
		Status = MmSecureVirtualMemory(Address, Size, NewProtect);
		sent->OldAccessProtection = NewProtect;

		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(&APC);

			ObfDereferenceObject(Process);

			return Status;
		}
		
		ProtectedAddress = Address;
		ProtectedSize = Size;

		MEMORY_BASIC_INFORMATION info;
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), Address, MemoryBasicInformation, &info, sizeof(MEMORY_BASIC_INFORMATION), NULL);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(&APC);

			ObfDereferenceObject(Process);

			return Status;
		}

		if (!(info.State & MEM_COMMIT)) {
			//ZwProtectVirtualMemory(ZwCurrentProcess(), &ProtectedAddress, &ProtectedSize, &OldProtection, OldProtection);
			MmSecureVirtualMemory(Address, Size, NewProtect);
			sent->OldAccessProtection = NewProtect;
			KeUnstackDetachProcess(&APC);

			ObfDereferenceObject(Process);

			Status = STATUS_ACCESS_DENIED;

			return Status;
		}

		KeUnstackDetachProcess(&APC);
		Status = STATUS_SUCCESS;
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		KeUnstackDetachProcess(&APC);
	}

	ObfDereferenceObject(Process);

	return Status;
}

NTSTATUS KeReadVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(Process, SourceAddress, PsGetCurrentProcess(),
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

NTSTATUS KeWriteVirtualMemory(PEPROCESS Process, PVOID SourceAddress, PVOID TargetAddress, SIZE_T Size)
{
	PSIZE_T Bytes;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), SourceAddress, Process,
		TargetAddress, Size, KernelMode, &Bytes)))
		return STATUS_SUCCESS;
	else
		return STATUS_ACCESS_DENIED;
}

BOOLEAN gotProcess = FALSE;
BOOLEAN gotNMCO = FALSE;

// set a callback for every PE image loaded to user memory
// then find the client.dll & csgo.exe using the callback
PLOAD_IMAGE_NOTIFY_ROUTINE ImageLoadCallback(PUNICODE_STRING FullImageName,
	HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	//DbgPrintEx(0, 0, "Loaded Name: %ls \n", FullImageName->Buffer);
	//DbgPrintEx(0, 0, "Loaded To Process: %d \n", ProcessId);

	// Compare our string to input
	/*
	__try {
			if (!FullImageName || !FullImageName->Buffer || !FullImageName->Length || !FullImageName->MaximumLength) return;

			//This is how you detect Atlantica.exe Process Id properly.
			if (wcsstr(FullImageName->Buffer, L"nmcogame.dll")) {
				// if it matches
				DbgPrintEx(0, 0, "NMCO Loaded Name: %ls \n", FullImageName->Buffer);
				DbgPrintEx(0, 0, "Loaded To Process: %d \n", ProcessId);

				GameBaseAddress = ImageInfo->ImageBase;
				GameProcessId = ProcessId;
				gotNMCO = TRUE;
			}

			if (ProcessId != 0 && ProcessId == GameProcessId) {
				GameBaseAddress = ImageInfo->ImageBase;
			}

    	    if(!FullImageName || !FullImageName->Buffer || !FullImageName->Length || !FullImageName->MaximumLength || !ProcessName.Length || !ProcessName.Buffer || !ProcessName.MaximumLength) return;

			if (!gotNMCO && !gotProcess && wcsstr(FullImageName->Buffer, ProcessName.Buffer)) {
				// if it matches
				DbgPrintEx(0, 0, "Loaded Name: %ls \n", FullImageName->Buffer);
				DbgPrintEx(0, 0, "Loaded To Process: %d \n", ProcessId);
	
				GameBaseAddress = ImageInfo->ImageBase;
				GameProcessId = ProcessId;
				gotProcess = TRUE;
			}
			
	} 
	__except (EXCEPTION_EXECUTE_HANDLER) 
	{ 
        	DbgPrintEx(0, 0, "Error UNICODE_STRING code: %X\n", GetExceptionCode());
	}
	*/
}

// IOCTL Call Handler function
NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	NTSTATUS Status;
	ULONG BytesIO = 0;

	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);

	// Code received from user space
	ULONG ControlCode = stack->Parameters.DeviceIoControl.IoControlCode;

	if (ControlCode == IO_READ_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PMEMORY_REQUEST ReadInput = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		PMEMORY_REQUEST ReadOutput = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		// Get our process
		if (NT_SUCCESS(PsLookupProcessByProcessId(ReadInput->ProcessId, &Process)))
			KeReadVirtualMemory(Process, ReadInput->read.Address,
				ReadInput->read.Response, ReadInput->read.Size);

		//DbgPrintEx(0, 0, "Read: PID: %lu, Address: %#010x, Buffer Address: %#010x\n", ReadInput->ProcessId, ReadInput->read.Address, ReadInput->read.Response);
		//DbgPrintEx(0, 0, "Value: %lu \n", &ReadOutput->read.Response);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(MEMORY_REQUEST);
	}
	else if (ControlCode == IO_WRITE_REQUEST)
	{
		// Get the input buffer & format it to our struct
		PMEMORY_REQUEST WriteInput = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		PEPROCESS Process;
		// Get our process
		if (NT_SUCCESS(PsLookupProcessByProcessId(WriteInput->ProcessId, &Process)))
			KeWriteVirtualMemory(Process, &WriteInput->write.Value,
				WriteInput->write.Address, WriteInput->write.Size);

		//DbgPrintEx(0, 0, "Write: PID: %lu, Value: %lu, Address: %#010x \n", WriteInput->ProcessId, WriteInput->write.Value, WriteInput->write.Address);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(MEMORY_REQUEST);
	}
	else if (ControlCode == IO_IS_VALID_ADDRESS)
	{
		// Get the input buffer & format it to our struct
		PVIRTUAL_QUERY_REQUEST ModuleInput = (PVIRTUAL_QUERY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		VirtualQueryInfo(ModuleInput);
		DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

		BOOLEAN isValid = (ModuleInput->info.Protect & mask);
		// check the page is not a guard page
		if (ModuleInput->info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) isValid = FALSE;

		PBOOLEAN isValidOut = (PBOOLEAN)Irp->AssociatedIrp.SystemBuffer;
		*isValidOut = isValid;

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(BOOLEAN);
	}
	else if (ControlCode == IO_SET_PROCESS_NAME_REQUEST)
	{
		ULONG inBufLength = stack->Parameters.DeviceIoControl.InputBufferLength; // Input buffer length
		ULONG outBufLength = stack->Parameters.DeviceIoControl.OutputBufferLength; // Output buffer length

		if (inBufLength == 0) {
			DbgPrint("Invalid Process name size detected\n");
			Status = STATUS_INVALID_PARAMETER;
			BytesIO = 0;
			goto finish;
		}

		PGET_PROCESS_ID_REQUEST processIdRequest = (PGET_PROCESS_ID_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		if (!processIdRequest->processName) {
			DbgPrint("Invalid Process name detected\n");
			Status = STATUS_INVALID_PARAMETER;
			BytesIO = 0;
			goto finish;
		}

		ULONG lengthOfProcessName = wcslen(processIdRequest->processName);

		if (lengthOfProcessName == 0) {
			DbgPrint("Invalid Process name size detected\n");
			Status = STATUS_INVALID_PARAMETER;
			BytesIO = 0;
			goto finish;
		}

		PWSTR processBuffer;

		// Allocate the buffer that will contain the string
		processBuffer = ExAllocatePoolWithTag(NonPagedPool, (lengthOfProcessName * 2) +2, '5PWA');
		if(processBuffer == NULL){
			DbgPrint("Unable to allocate the Process Buffer: not enough memory.\n");
			Status = STATUS_INSUFFICIENT_RESOURCES;
			BytesIO = 0;
			goto finish;
		}

		// Copy the buffer
		RtlCopyBytes((PVOID)processBuffer, processIdRequest->processName, (lengthOfProcessName * 2));
		//RtlMoveMemory((PVOID)processBuffer, processIdRequest->processName, lengthOfProcessName);

		// Force a \0 at the end of the filename to avoid that malformed strings cause RtlInitUnicodeString to crash the system
		((PSHORT)processBuffer)[((lengthOfProcessName*2) +2)/2-1]=0;
		
		GameProcessId = FindProcessByName(processBuffer);
		
		DbgPrint("Set New Process to %ws, len=%d pid=%llu\n", processBuffer, lengthOfProcessName, GameProcessId);

		ExFreePool(processBuffer);

		processIdRequest->ProcessId = GameProcessId;
		Status = STATUS_SUCCESS;
		BytesIO = sizeof(GET_PROCESS_ID_REQUEST);
	}
	else if (ControlCode == IO_GET_MODULE_REQUEST)
	{
		PMEMORY_REQUEST ModuleInput = (PMEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;
		
		SearchProcessModules(ModuleInput);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(MEMORY_REQUEST);
	}
	else if (ControlCode == IO_VIRTUAL_QUERY_REQUEST)
	{
		PVIRTUAL_QUERY_REQUEST ModuleInput = (PVIRTUAL_QUERY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		VirtualQueryInfo(ModuleInput);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(VIRTUAL_QUERY_REQUEST);
	}
	else if (ControlCode == IO_PROTECT_VIRTUAL_MEMORY_REQUEST)
	{
		PPROTECT_VIRTUAL_MEMORY_REQUEST ProtectVirtualMemoryRequest = (PPROTECT_VIRTUAL_MEMORY_REQUEST)Irp->AssociatedIrp.SystemBuffer;

		ForceProtectVirtualMemory(ProtectVirtualMemoryRequest);

		Status = STATUS_SUCCESS;
		BytesIO = sizeof(PROTECT_VIRTUAL_MEMORY_REQUEST);
	}
	else if (ControlCode == IO_GET_BASE_ADDRESS)
	{
		PULONG OutPut = (PULONG)Irp->AssociatedIrp.SystemBuffer;
		*OutPut = GameBaseAddress;

		DbgPrintEx(0, 0, "game base address module: %#010x", GameBaseAddress);
		Status = STATUS_SUCCESS;
		BytesIO = sizeof(*OutPut);
	}
	else
	{
		 // if the code is unknown
		Status = STATUS_INVALID_PARAMETER;
		BytesIO = 0;
	}
finish:
	// Complete the request
	Irp->IoStatus.Status = Status;
	Irp->IoStatus.Information = BytesIO;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	
	return Status;
}

// Driver Entrypoint
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath)
{
	DbgPrintEx(0, 0, "Driver Loaded\n");

	//TODO: Disabled not needed anymore got GetProcessByName(), plus this causes BSOD with wcsstr() - HighGamer
	//PsSetLoadImageNotifyRoutine(ImageLoadCallback);

	RtlInitUnicodeString(&dev, deviceNameBuffer);
	RtlInitUnicodeString(&dos, deviceSymLinkBuffer);

	IoCreateDevice(pDriverObject, 0, &dev, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	IoCreateSymbolicLink(&dos, &dev);

	pDriverObject->MajorFunction[IRP_MJ_CREATE] = CreateCall;
	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = CloseCall;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	pDriverObject->DriverUnload = UnloadDriver;

	pDeviceObject->Flags |= DO_DIRECT_IO;
	pDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

	return STATUS_SUCCESS;
}



NTSTATUS UnloadDriver(PDRIVER_OBJECT pDriverObject)
{
	DbgPrintEx(0, 0, "Unload routine called.\n");

	PsRemoveLoadImageNotifyRoutine(ImageLoadCallback);
	IoDeleteSymbolicLink(&dos);
	IoDeleteDevice(pDriverObject->DeviceObject);
}

NTSTATUS CreateCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS CloseCall(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	irp->IoStatus.Status = STATUS_SUCCESS;
	irp->IoStatus.Information = 0;

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}
