/* Cheat that uses a driver for reading / writing virtual memory,
instead of using Win32API Functions. Written By Zer0Mem0ry,
https://www.youtube.com/watch?v=sJdBtPosWQs */

#include <Windows.h>
#include <vector>
#include <string>

/* IOCTL Codes needed for our driver */

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

// Offset to force jump action
#define FORCE_JUMP 0x04F5FD5C
// offset to local player
#define LOCAL_PLAYER 0x00AA66D4

#define FFLAGS 0x00000100


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
} KERNEL_READ_REQUEST, * PKERNEL_READ_REQUEST;

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
} KERNEL_MODULE_REQUEST, * PKERNEL_MODULE_REQUEST;

typedef struct _MEMORY_REQUEST
{
	ULONG ProcessId;
	KERNEL_READ_REQUEST read;
	KERNEL_WRITE_REQUEST write;
	KERNEL_MODULE_REQUEST module;
} MEMORY_REQUEST;

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


// interface for our driver
class KeInterface
{
public:
	HANDLE hDriver; // Handle to driver

					// Initializer
	KeInterface::KeInterface(LPCSTR RegistryPath)
	{
		hDriver = CreateFileA(RegistryPath, GENERIC_READ | GENERIC_WRITE,
			FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	}

	template <typename type>
	type ReadVirtualMemory(ULONG ProcessId, ULONG ReadAddress,
		SIZE_T Size, PVOID OutputBuffer = NULL)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return (type)NULL;

		DWORD dwBytes;
		MEMORY_REQUEST memoryRequest = { 0 };

		type ReturnValue = NULL;

		memoryRequest.ProcessId = ProcessId;
		memoryRequest.read.Address = ReadAddress;
		memoryRequest.read.Size = Size;
		if (OutputBuffer)
			memoryRequest.read.Response = OutputBuffer;
		else
			memoryRequest.read.Response = static_cast<void*>(&ReturnValue);

		// send code to our driver with the arguments
		if (DeviceIoControl(hDriver, IO_READ_REQUEST, &memoryRequest,
			sizeof(memoryRequest), &memoryRequest, sizeof(memoryRequest), &dwBytes, NULL))
			return (type)(OutputBuffer ? 0 : ReturnValue);
		else
			return (type)NULL;
	}

	template <typename type>
	std::basic_string<type> ReadString(ULONG ProcessId, ULONG ReadAddress, SIZE_T Size = 256)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return (type)NULL;

		DWORD dwBytes;
		MEMORY_REQUEST memoryRequest = { 0 };

		std::basic_string<type> buffer(Size, type());

		memoryRequest.ProcessId = ProcessId;
		memoryRequest.read.Address = ReadAddress;
		memoryRequest.read.Size = buffer.size();
		memoryRequest.read.Response = static_cast<void*>(&buffer[0]);

		// send code to our driver with the arguments
		if (DeviceIoControl(hDriver, IO_READ_REQUEST, &memoryRequest,
			sizeof(memoryRequest), &memoryRequest, sizeof(memoryRequest), &dwBytes, NULL))
			return std::basic_string<type>(buffer.data());
		else
			return std::basic_string<type>();
	}

	bool WriteVirtualMemory(ULONG ProcessId, ULONG WriteAddress,
		ULONG WriteValue, SIZE_T WriteSize)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;
		DWORD dwBytes;

		MEMORY_REQUEST memoryRequest = { 0 };

		memoryRequest.ProcessId = ProcessId;
		memoryRequest.write.Address = WriteAddress;
		memoryRequest.write.Value = (PVOID)WriteValue;
		memoryRequest.write.Size = WriteSize;
		
		if (DeviceIoControl(hDriver, IO_WRITE_REQUEST, &memoryRequest, sizeof(memoryRequest),
			0, 0, &dwBytes, NULL))
			return true;
		else
			return false;
	}

	BOOLEAN IsValidAddress(ULONG ProcessId, ULONG ReadAddress)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return 0;

		DWORD dwBytes;
		BOOLEAN isValid = FALSE;

		//TODO: Only reason this works is because it recasts ProcessId to BOOLEAN lol could be risky if struct changes. - HighGamer

		VIRTUAL_QUERY_REQUEST moduleList;
		moduleList.ProcessId = ProcessId;
		moduleList.Address = ReadAddress;

		if (DeviceIoControl(hDriver, IO_IS_VALID_ADDRESS, (LPVOID)&moduleList, sizeof(VIRTUAL_QUERY_REQUEST),
			&isValid, sizeof(BOOLEAN), &dwBytes, NULL))
			return isValid;
		else
			return FALSE;
	}

	DWORD GetModulesInformation(MEMORY_REQUEST* moduleList)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return 0;

		DWORD dwBytes;

		if (DeviceIoControl(hDriver, IO_GET_MODULE_REQUEST, moduleList,
			sizeof(MEMORY_REQUEST), moduleList, sizeof(MEMORY_REQUEST), &dwBytes, NULL))
			return 1;
		else
			return 0;
	}

	DWORD VirtualQueryInfo(VIRTUAL_QUERY_REQUEST* moduleList)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return 0;

		DWORD dwBytes;

		if (DeviceIoControl(hDriver, IO_VIRTUAL_QUERY_REQUEST, moduleList,
			sizeof(VIRTUAL_QUERY_REQUEST), moduleList, sizeof(VIRTUAL_QUERY_REQUEST), &dwBytes, NULL))
			return 1;
		else
			return 0;
	}

	DWORD ProtectVirtualMemory(PROTECT_VIRTUAL_MEMORY_REQUEST* virtualMemoryRequest)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return 0;

		DWORD dwBytes = 0;
		if (DeviceIoControl(hDriver, IO_PROTECT_VIRTUAL_MEMORY_REQUEST, virtualMemoryRequest,
			sizeof(PROTECT_VIRTUAL_MEMORY_REQUEST), virtualMemoryRequest, sizeof(PROTECT_VIRTUAL_MEMORY_REQUEST), &dwBytes, NULL))
			return 1;
		else
			return 0;
	}

	DWORD GetTargetProcessId(wchar_t* processName)
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;

		DWORD dwBytes;

		GET_PROCESS_ID_REQUEST processIdRequest;
		processIdRequest.ProcessId = 0;
		wcscpy(processIdRequest.processName, processName);

		if (DeviceIoControl(hDriver, IO_SET_PROCESS_NAME_REQUEST, &processIdRequest, sizeof(GET_PROCESS_ID_REQUEST),
			&processIdRequest, sizeof(GET_PROCESS_ID_REQUEST), &dwBytes, NULL))
			return processIdRequest.ProcessId;
		else
			return 0;
	}

	DWORD GetClientBaseAddressModule()
	{
		if (hDriver == INVALID_HANDLE_VALUE)
			return false;

		ULONG Address;
		DWORD dwBytes;

		if (DeviceIoControl(hDriver, IO_GET_BASE_ADDRESS, &Address, sizeof(Address),
			&Address, sizeof(Address), &dwBytes, NULL))
			return Address;
		else
			return false;
	}
};
