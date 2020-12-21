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

#include "CMemoryScanner.h"
#include "MemUtils.h"
#include "Main.h"

using namespace std;
//----------------------------------------------------------------------------------------------------------------------

string str;

void CMemoryScanner::InitAddr(HWND hDlg, int nIDDlgItem, DWORD dwAddr, DWORD dwOffs)
{
	BYTE bVal;
	//if(ReadProcessMemory(GetCurrentProcess(), (void*)(dwAddr+dwOffs), &bVal, 1, NULL))
	//bVal = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, (dwAddr + dwOffs), 1);
	//if (IsBadReadPtr((PDWORD)(dwAddr + dwOffs), 1) == 0)
	if (Driver.IsValidAddress(CURRENT_PROCESS_ID, (dwAddr + dwOffs)))
	{
		//bVal = *(PBYTE)(dwAddr + dwOffs);
		bVal = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, (dwAddr + dwOffs), 1);
		SetDlgItemTextA(hDlg, nIDDlgItem, IntToHex(bVal).c_str());
	}
	else
	{
		str += ". ";
		SetDlgItemTextA(hDlg, nIDDlgItem, "??");
	}
}

void CMemoryScanner::ShowValues(HWND hDlg, int nIDDlgItem, DWORD dwAddr, DWORD type, BOOLEAN isString, BOOLEAN isUnicode)
{
	BYTE bVal;
	WORD wVal;
	DWORD dVal;
	std::basic_string<char> asciiString;
	std::basic_string<wchar_t> unicodeString;

	//if(ReadProcessMemory(GetCurrentProcess(), (void*)(dwAddr+dwOffs), &bVal, 1, NULL))
	//bVal = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, (dwAddr + dwOffs), 1);
	//if (IsBadReadPtr((PDWORD)(dwAddr + dwOffs), 1) == 0)
	if (Driver.IsValidAddress(CURRENT_PROCESS_ID, dwAddr))
	{
		//bVal = *(PBYTE)(dwAddr + dwOffs);
		if (isString) {
			if (isUnicode) {
				unicodeString = Driver.ReadString<wchar_t>(CURRENT_PROCESS_ID, dwAddr, type * 2);
				char *str = new char[4046];
				wcstombs(str, unicodeString.c_str(), wcslen(unicodeString.c_str()));
				SetDlgItemTextA(hDlg, nIDDlgItem, str);
				delete[] str;
			} else {
				asciiString = Driver.ReadString<char>(CURRENT_PROCESS_ID, dwAddr, type);
				SetDlgItemTextA(hDlg, nIDDlgItem, asciiString.c_str());
			}
		}
		else if (type == 1) {
			bVal = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, dwAddr, type);
			SetDlgItemTextA(hDlg, nIDDlgItem, IntToHex(bVal).c_str());
		}
		else if (type == 2) {
			wVal = Driver.ReadVirtualMemory<WORD>(CURRENT_PROCESS_ID, dwAddr, type);
			SetDlgItemTextA(hDlg, nIDDlgItem, IntToHex(wVal).c_str());
		}
		else if (type == 4) {
			dVal = Driver.ReadVirtualMemory<DWORD>(CURRENT_PROCESS_ID, dwAddr, type);
			SetDlgItemTextA(hDlg, nIDDlgItem, IntToHex(dVal).c_str());
		}
	}
	else
	{
		SetDlgItemTextA(hDlg, nIDDlgItem, "??");
	}
}

void CMemoryScanner::Value2Char(HWND hDlg, int nIDDlgItem, DWORD dwAddr)
{
	char buf[10];
	string str;
	BYTE bVal;
	int j = 0;

	//SetDlgItemTextA(hDlg, ID, ". . . . . . . . . . . . . . . .");
	for (int IndexChar = 0; IndexChar <= 255; IndexChar += 16)
	{
		for (int i = 0; i <= 15; i++)
		{
			//if(ReadProcessMemory(GetCurrentProcess(), (void*)(dwAddr+IndexChar+i), &bVal, 1, NULL))
			//bVal = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, (dwAddr + IndexChar + i), 1);
			//if (IsBadReadPtr((PDWORD)(dwAddr + IndexChar + i), 1) == 0)
			if (Driver.IsValidAddress(CURRENT_PROCESS_ID, (dwAddr + IndexChar + i)))
			{
				bVal = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, (dwAddr + IndexChar + i), 1);
				//bVal = *(PBYTE)(dwAddr + IndexChar + i);
				if (bVal == 20)str += " ";
				else if (bVal < 33)str += ". ";
				else
				{
					sprintf_s(buf, "%c", bVal);
					str += buf;
				}
			}
		}

		SetDlgItemTextA(hDlg, nIDDlgItem + j, str.c_str());
		str = "";
		j++;
	}
}

void CMemoryScanner::EditMemory(DWORD dwAddress, BYTE bVal)
{

	Driver.WriteVirtualMemory(CURRENT_PROCESS_ID, dwAddress, bVal, 1);

	/*
	DWORD dwOld;
	if (VirtualProtect((void*)dwAddress, 1, 0x40, &dwOld))//jika sukses
	{
		if (IsBadReadPtr((PDWORD)dwAddress, 1) == 0)
		{
			//memcpy((void*)dwAddress, (void*)&bVal, 1);
			*(PBYTE)dwAddress = bVal;
			VirtualProtect((void*)dwAddress, 1, dwOld, &dwOld);
		}
	}
	*/
}

void CMemoryScanner::EditMemory(DWORD dwAddress, DWORD dwVal, DWORD type)
{

	Driver.WriteVirtualMemory(CURRENT_PROCESS_ID, dwAddress, dwVal, type);

	/*
	DWORD dwOld;
	if (VirtualProtect((void*)dwAddress, 1, 0x40, &dwOld))//jika sukses
	{
		if (IsBadReadPtr((PDWORD)dwAddress, type) == 0)
		{
			memcpy((void*)dwAddress, (void*)&dwVal, type);
			VirtualProtect((void*)dwAddress, 1, dwOld, &dwOld);
		}
	}
	*/
}

void CMemoryScanner::EditString(DWORD dwAddress, string strVal, BOOLEAN isUnicode)
{
	DWORD unicodeCount = 0;
	for (DWORD i = 0; i <= strVal.length(); i++) {
		if (isUnicode) {
			Driver.WriteVirtualMemory(CURRENT_PROCESS_ID, (dwAddress + i + unicodeCount), (BYTE)strVal[i], 1);
			Driver.WriteVirtualMemory(CURRENT_PROCESS_ID, (dwAddress + i + unicodeCount + 1), (BYTE)0, 1);
			unicodeCount++;
		} else {
			Driver.WriteVirtualMemory(CURRENT_PROCESS_ID, (dwAddress + i), (BYTE)strVal[i], 1);
		}
	}
	/*
	DWORD dwOld;
	if (VirtualProtect((void*)dwAddress, strVal.length(), 0x40, &dwOld))//jika sukses
	{
		for (DWORD i = 0; i <= strVal.length(); i++)
			memcpy((void*)(dwAddress + i), (void*)&strVal[i], 1);

		VirtualProtect((void*)dwAddress, strVal.length(), dwOld, &dwOld);
	}
	*/
}