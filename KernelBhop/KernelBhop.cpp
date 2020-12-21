/* Cheat that uses a driver for reading / writing virtual memory,
instead of using Win32API Functions. Written By Zer0Mem0ry,
https://www.youtube.com/watch?v=sJdBtPosWQs */

#include <iostream>

#ifndef KE_INTERFACE_INCLUDED
#define KE_INTERFACE_INCLUDED
	#include "KeInterface.h"
#endif

#include "Main.h"
#include "MemFunctions.h"
#include "CMemoryScanner.h"
#include "CDialogUtils.h"
#include "FMemScan.h"

CMemFunctions *MemFunctions = NULL;

KeInterface Driver("\\\\.\\kernelhop");

DWORD CURRENT_PROCESS_ID;
WCHAR CURRENT_PROCESS_NAME[MAX_PATH + 1] = { 0 };

void _stdcall MainThread(LPVOID hDLLModule)
{
	DialogBoxParamA((HINSTANCE)hDLLModule, MAKEINTRESOURCEA(IDD_DIALOG1), NULL, DLGPROC(DialogProc), NULL);
}


int main()
{
	if (MemFunctions == nullptr)
		MemFunctions = new CMemFunctions();

	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)MainThread, (LPVOID)GetModuleHandle(NULL), NULL, NULL);

	//This so the program doesn't end lol.
	while (true)
		Sleep(10000);

	/*
	
	ULONG pid = Driver.GetTargetProcessId(L"calc.exe");
	printf("Test Process ID set to = %d\n", pid);
	BOOL test = Driver.IsValidAddress(pid, 0x360000);

	printf("test = %d\n", test);

	DWORD testDWORD = Driver.ReadVirtualMemory<DWORD>(pid, 0x016B008, sizeof(DWORD));
	printf("value of DWORD = %lu [%x]\n", testDWORD, testDWORD);
	WORD testWORD = Driver.ReadVirtualMemory<WORD>(pid, 0x016B008, sizeof(WORD));
	printf("value of WORD = %lu [%x]\n", testWORD, testWORD);
	BYTE testBYTE = Driver.ReadVirtualMemory<BYTE>(pid, 0x016B008, sizeof(BYTE));
	printf("value of BYTE = %lu [%x]\n", testBYTE, testBYTE);
	string testASCIIString = Driver.ReadString<char>(pid, 0x016B008, 10);
	printf("value of ASCII = %s\n", testASCIIString);
	wstring testUNICODEString = Driver.ReadString<wchar_t>(pid, 0x016B008, 10);
	printf("value of UNICODE = %s, %ls\n", testUNICODEString, testUNICODEString);

	VIRTUAL_QUERY_REQUEST queryRequest;
	ZeroMemory(&queryRequest, sizeof(VIRTUAL_QUERY_REQUEST));

	queryRequest.ProcessId = pid;
	queryRequest.Address = 0x02D1000;

	if (Driver.VirtualQueryInfo(&queryRequest)) {
		printf("info = %X %X\n", queryRequest.info.BaseAddress, queryRequest.info.RegionSize);
	}

	MEMORY_REQUEST moduleRetieve;
	ZeroMemory(&moduleRetieve, sizeof(MEMORY_REQUEST));

	moduleRetieve.ProcessId = pid;
	wcsncpy_s(moduleRetieve.module.moduleName, L"ntdll.dll", 1024);

	Driver.GetModulesInformation(&moduleRetieve);

	printf("Module: %ws Base: %X Size : %X\n", moduleRetieve.module.buffer.Name, moduleRetieve.module.buffer.Base, moduleRetieve.module.buffer.Size);

	DWORD ClientBaseAddress = Driver.GetClientBaseAddressModule();

	// Get address of localplayer
	DWORD LocalPlayer = Driver.ReadVirtualMemory<DWORD>(pid, ClientBaseAddress + LOCAL_PLAYER, sizeof(ULONG));

	// address of inground
	DWORD InGround = Driver.ReadVirtualMemory<DWORD>(pid, LocalPlayer + FFLAGS, sizeof(ULONG));

	// check that addresses were found

	printf("Found Process Id: %d [%x]\n", pid, pid);
	printf("Found BaseAddress Module: 0x%x\n", ClientBaseAddress);

	std::cout << "Found LocalPlayer in client.dll: 0x" << std::uppercase
		<< std::hex << LocalPlayer << std::endl;
	std::cout << "Found PlayerInGround: 0x" << std::uppercase
		<< std::hex << InGround << std::endl;

	while (true)
	{
		// Constantly check if player is in ground
		DWORD InGround = Driver.ReadVirtualMemory<DWORD>(pid, LocalPlayer + FFLAGS, sizeof(ULONG));
		// Check if space is down & player is in ground
		if ((GetAsyncKeyState(VK_SPACE) & 0x8000) && (InGround & 1 == 1))
		{
			// Jump
			Driver.WriteVirtualMemory(pid, ClientBaseAddress + FORCE_JUMP, 0x5, 8);
			Sleep(50);
			// Restore
			Driver.WriteVirtualMemory(pid, ClientBaseAddress + FORCE_JUMP, 0x4, 8);
			
		}
		Sleep(10);
	}
	*/
    return 0;
}

