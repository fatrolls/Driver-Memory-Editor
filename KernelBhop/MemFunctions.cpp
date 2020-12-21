#include <Windows.h>
#include <stdio.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string.h>
#include <psapi.h>
#include <shlwapi.h>
#include <shlobj.h>

#pragma comment (lib, "psapi.lib")
#pragma comment (lib, "shlwapi.lib")

#include "MemFunctions.h"

//----------------------------------------------------------------------------------------------------------------------

CMemFunctions::CMemFunctions()
{
	if (Initialize())
		m_bIsInitialized = TRUE;
}


CMemFunctions::~CMemFunctions()
{
	if (m_hModNtdll)
		MemoryFreeLibrary(m_hModNtdll);
}

BOOL CMemFunctions::Initialize()
{
	BOOL bRet = TRUE;
	CHAR szSystemDir[MAX_PATH + 1] = { 0 };
	FILE *fp = NULL;
	void *dllData = NULL;
	SIZE_T dllSize = 0;

	if (SHGetSpecialFolderPathA(NULL, szSystemDir, CSIDL_SYSTEMX86, FALSE) == FALSE)
		return FALSE;

#if DEBUG
	ODS("szSystemDir: %s\n", szSystemDir);
#endif

	strcat_s(szSystemDir, "\\ntdll.dll");

#if DEBUG
	ODS("szSystemDir: %s\n", szSystemDir);
#endif

	if (PathFileExistsA(szSystemDir) == FALSE)
		return FALSE;

#if DEBUG
	ODS("szSystemDir: %s exists\n", szSystemDir);
#endif

	errno_t errorCode = fopen_s(&fp, szSystemDir, "rb");
	if (errorCode != NULL)
		return FALSE;

#if DEBUG
	ODS("szSystemDir: %s fopen\n", szSystemDir);
#endif

	fseek(fp, 0, SEEK_END);
	dllSize = ftell(fp);

#if DEBUG
	ODS("dllSize: %d\n", dllSize);
#endif

	dllData = malloc(dllSize);
	if (dllData == NULL)
		return FALSE;

#if DEBUG
	ODS("szSystemDir: %s malloc", szSystemDir);
#endif

	fseek(fp, 0, SEEK_SET);
	fread(dllData, 1, dllSize, fp);
	fclose(fp);

#if DEBUG
	ODS("dllData: %p size %d", dllData, dllSize);
#endif

	/*
	m_hModNtdll = MemoryLoadLibrary(dllData);
	if (m_hModNtdll == NULL)
	{
#if DEBUG
		ODS("MemoryLoadLibrary Error");
#endif
		goto FAILED;
	}
	*/

/*
#if DEBUG
ODS("szSystemDir: %s MemoryLoadLibrary", szSystemDir);
#endif

pNtProtectVirtualMemory = (tNtProtectVirtualMemory)GetProcAddress(hOriginalDll, "NtProtectVirtualMemory");
if (pNtProtectVirtualMemory == NULL)
goto FAILED;

#if DEBUG
ODS("NtProtectVirtualMemory: %p OK", pNtProtectVirtualMemory);
#endif

pNtQueryVirtualMemory = (tNtQueryVirtualMemory)GetProcAddress(hOriginalDll, "NtQueryVirtualMemory");
if (pNtQueryVirtualMemory == NULL)
goto FAILED;

#if DEBUG
ODS("NtQueryVirtualMemory: %p OK", pNtQueryVirtualMemory);
#endif

pNtReadVirtualMemory = (tNtReadVirtualMemory)GetProcAddress(hOriginalDll, "NtReadVirtualMemory");
if (pNtReadVirtualMemory == NULL)
goto FAILED;

#if DEBUG
ODS("NtReadVirtualMemory: %p OK", pNtReadVirtualMemory);
#endif

pNtWriteVirtualMemory = (tNtWriteVirtualMemory)GetProcAddress(hOriginalDll, "NtWriteVirtualMemory");
if (pNtWriteVirtualMemory == NULL)
goto FAILED;

#if DEBUG
ODS("NtWriteVirtualMemory: %p OK", pNtWriteVirtualMemory);
#endif
*/

	hOriginalDll = ::LoadLibraryA(szSystemDir);

#if DEBUG
	ODS("hOriginalDll: %x %s", hOriginalDll, szSystemDir);
#endif

	pNtProtectVirtualMemory = (tNtProtectVirtualMemory)GetProcAddress(hOriginalDll, "NtProtectVirtualMemory");
	if (pNtProtectVirtualMemory == NULL)
		goto FAILED;

#if DEBUG
	ODS("NtProtectVirtualMemory: %p OK", pNtProtectVirtualMemory);
#endif

	pNtQueryVirtualMemory = (tNtQueryVirtualMemory)GetProcAddress(hOriginalDll, "NtQueryVirtualMemory");
	if (pNtQueryVirtualMemory == NULL)
		goto FAILED;

#if DEBUG
	ODS("NtQueryVirtualMemory: %p OK", pNtQueryVirtualMemory);
#endif

	pNtReadVirtualMemory = (tNtReadVirtualMemory)GetProcAddress(hOriginalDll, "NtReadVirtualMemory");
	if (pNtReadVirtualMemory == NULL)
		goto FAILED;

#if DEBUG
	ODS("NtReadVirtualMemory: %p OK", pNtReadVirtualMemory);
#endif

	pNtWriteVirtualMemory = (tNtWriteVirtualMemory)GetProcAddress(hOriginalDll, "NtWriteVirtualMemory");
	if (pNtWriteVirtualMemory == NULL)
		goto FAILED;

#if DEBUG
	ODS("NtWriteVirtualMemory: %p OK", pNtWriteVirtualMemory);
#endif
	
	goto SUCCESS;

FAILED:
	bRet = FALSE;

SUCCESS:
	free(dllData);
	return bRet;
}

NTSTATUS NTAPI CMemFunctions::NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress, PULONG NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection)
{
	return pNtProtectVirtualMemory(ProcessHandle, BaseAddress, NumberOfBytesToProtect, NewAccessProtection, OldAccessProtection);
}

NTSTATUS NTAPI CMemFunctions::NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, MEMORY_INFORMATION_CLASS MemoryInformationClass, PVOID Buffer, ULONG Length, PULONG ResultLength)
{
	return pNtQueryVirtualMemory(ProcessHandle, BaseAddress, MemoryInformationClass, Buffer, Length, ResultLength);
}

NTSTATUS NTAPI CMemFunctions::NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded)
{
	return pNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

NTSTATUS NTAPI CMemFunctions::NtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten)
{
	return pNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToWrite, NumberOfBytesWritten);
}

void *CMemFunctions::DetourCreate(BYTE *src, const BYTE *dst, const int len)
{
	PVOID pAddr = (PVOID)src;
	DWORD pSize = (DWORD)len;
	DWORD OldProtect = NULL;

	if (NtProtectVirtualMemory(GetCurrentProcess(), &pAddr, &pSize, PAGE_EXECUTE_READWRITE, &OldProtect) == 0)
	{
		BYTE *jmp = (PBYTE)malloc(len + 5);
		memcpy(jmp, src, len);
		jmp += len;
		jmp[0] = 0xE9;
		*(PDWORD)(jmp + 1) = (DWORD)(src + len - jmp) - 5;
		src[0] = 0xE9;
		*(PDWORD)(src + 1) = (DWORD)(dst - src) - 5;
		for (int i = 5; i < len; i++)
			src[i] = 0x90;
		NtProtectVirtualMemory(GetCurrentProcess(), &pAddr, &pSize, OldProtect, &OldProtect);

		return (jmp - len);
	}

	return src;
}