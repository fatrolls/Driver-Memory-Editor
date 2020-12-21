#pragma once

#include "MemoryModule.h"

class CMemFunctions
{
public:
	CMemFunctions();
	~CMemFunctions();

	typedef enum _MEMORY_INFORMATION_CLASS
	{
		MemoryBasicInformation
	}MEMORY_INFORMATION_CLASS, *PMEMORY_INFORMATION_CLASS;

	typedef struct _CLIENT_ID
	{
		PVOID UniqueProcess;
		PVOID UniqueThread;
	}CLIENT_ID, *PCLIENT_ID;

	typedef struct _INITIAL_TEB
	{
		PVOID StackBase;
		PVOID StackLimit;
		PVOID StackCommit;
		PVOID StackCommitMax;
		PVOID StackReserved;
	}INITIAL_TEB, *PINITIAL_TEB;

	BOOL IsInitialized()
	{
		return m_bIsInitialized;
	}

	NTSTATUS NTAPI NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);
	NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, ULONG Length, PULONG ResultLength);
	NTSTATUS NTAPI NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded);
	NTSTATUS NTAPI NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

	void *DetourCreate(BYTE *src, const BYTE *dst, const int len);

private:
	typedef NTSTATUS(NTAPI *tNtProtectVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN OUT PVOID *BaseAddress,
		IN OUT PULONG NumberOfBytesToProtect,
		IN ULONG NewAccessProtection,
		OUT PULONG OldAccessProtection);

	typedef NTSTATUS(NTAPI *tNtQueryVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN MEMORY_INFORMATION_CLASS MemoryInformationClass,
		OUT PVOID Buffer,
		IN ULONG Length,
		OUT PULONG ResultLength OPTIONAL);

	typedef NTSTATUS(NTAPI *tNtReadVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		OUT PVOID Buffer,
		IN ULONG NumberOfBytesToRead,
		OUT PULONG NumberOfBytesReaded);

	typedef NTSTATUS(NTAPI *tNtWriteVirtualMemory)(
		IN HANDLE ProcessHandle,
		IN PVOID BaseAddress,
		IN PVOID Buffer,
		IN ULONG NumberOfBytesToWrite,
		IN PULONG NumberOfBytesWritten);

	tNtProtectVirtualMemory pNtProtectVirtualMemory = nullptr;
	tNtQueryVirtualMemory pNtQueryVirtualMemory = nullptr;
	tNtReadVirtualMemory pNtReadVirtualMemory = nullptr;
	tNtWriteVirtualMemory pNtWriteVirtualMemory = nullptr;

	typedef void *HMEMORYMODULE;
	HMEMORYMODULE m_hModNtdll;

	HINSTANCE  hOriginalDll;

	BOOL m_bIsInitialized = FALSE;
	BOOL Initialize();
};

