#include "resource.h"

#define WRITABLE (PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

HWND hDlgProc = NULL;

extern CMemFunctions *MemFunctions;

//----------------------------------------------------------------------------------------------------------------------

void _stdcall FinishFirstScan()
{
	HWND hWndList1 = GetDlgItem(hDlgProc, IDC_LIST1);
	_ASSERTE(hWndList1 != NULL);
	int itemCount = (int)SendMessageA(hWndList1, LB_GETCOUNT, (WPARAM)0, (LPARAM)0);
	if (itemCount != LB_ERR)
	{
		string sfound = "Found : ";
		sfound += IntToStr(itemCount);
		SetDlgItemTextA(hDlgProc, IDC_FOUND, sfound.c_str());
	}

	EnableWindow(GetDlgItem(hDlgProc, IDC_BTNNEXTSCAN), TRUE);
}

//----------------------------------------------------------------------------------------------------------------------

void _stdcall FinishNextScan()
{
	SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_RESETCONTENT, 0, 0);
	HWND hWndList2 = GetDlgItem(hDlgProc, IDC_LIST2);
	_ASSERTE(hWndList2 != NULL);
	int itemCount = (int)SendMessageA(hWndList2, LB_GETCOUNT, (WPARAM)0, (LPARAM)0);
	if (itemCount != LB_ERR)
	{
		string sfound = "Found : ";
		sfound += IntToStr(itemCount);
		SetDlgItemTextA(hDlgProc, IDC_FOUND, sfound.c_str());

		for (int i = 0; i <= itemCount - 1; i++)
		{
			//Get length of text in listbox
			int textLen = (int)SendMessageA(hWndList2, LB_GETTEXTLEN, (WPARAM)i, 0);
			//Allocate buffer to store text (consider +1 for end of string)
			char buffer[256];
			//Get actual text in buffer
			SendMessageA(hWndList2, LB_GETTEXT, (WPARAM)i, (LPARAM)buffer);
			//add to list1
			SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)buffer);
		}
	}

	EnableWindow(GetDlgItem(hDlgProc, IDC_BTNNEXTSCAN), TRUE);
}

//----------------------------------------------------------------------------------------------------------------------

bool timer = true, bcancel = false;

void _fastcall Scan(DWORD dwStart, DWORD dwEnd, DWORD dwVal, DWORD dwLength)
{
	DWORD temp = 0;
	ULONG BytesReaded = NULL;
	char val[25];
	char tempBuffer[256] = { 0 };

	bcancel = false;
	timer = true;

	while (1)
	{
		if (bcancel)//batalkan scan
			goto cancel;

		if (CURRENT_PROCESS_ID == 0) {
			MessageBoxA(0, "Process Id is zero cannot do search click Change Process", "Information", MB_ICONINFORMATION);
			goto cancel;
		}

		VIRTUAL_QUERY_REQUEST queryRequest;
		ZeroMemory(&queryRequest, sizeof(VIRTUAL_QUERY_REQUEST));

		queryRequest.ProcessId = CURRENT_PROCESS_ID;
		queryRequest.Address = dwStart;

		if (!Driver.VirtualQueryInfo(&queryRequest))
			goto cancel;
		
		if (queryRequest.info.State & MEM_COMMIT && queryRequest.info.Protect & WRITABLE)
		{
			sprintf(tempBuffer, "Scanning: 0x%X\\0x%X", dwStart, queryRequest.info.RegionSize);
			SetDlgItemTextA(hDlgProc, IDC_SCANNING, tempBuffer);

			if (IsDlgButtonChecked(hDlgProc, IDC_FASTSCAN))
			{
				unsigned char* MEMORY = new unsigned char[queryRequest.info.RegionSize];
				Driver.ReadVirtualMemory<unsigned char>(CURRENT_PROCESS_ID, dwStart, queryRequest.info.RegionSize, MEMORY);

				for (DWORD i = 0; i <= (DWORD)queryRequest.info.RegionSize; i += dwLength)
				{
					if (bcancel)//batalkan scan
						goto cancel;

					if (dwLength == 1) 
						temp = *(BYTE *)(&MEMORY[i]);
					else if (dwLength == 2)
						temp = *(WORD *)(&MEMORY[i]);
					else if(dwLength == 4)
						temp = *(DWORD *)(&MEMORY[i]);

					if (temp == dwVal)
					{
						sprintf_s(val, "%08X      %d", (dwStart + i), temp);
						SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
					}
				}

				delete[] MEMORY;
			} else {
				for (DWORD i = dwStart; i <= (DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize; i += dwLength)
				{
					if (bcancel)//batalkan scan
						goto cancel;

					temp = Driver.ReadVirtualMemory<DWORD>(CURRENT_PROCESS_ID, i, dwLength);

					if (temp == dwVal)
					{
						sprintf_s(val, "%08X      %d", i, temp);
						SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
					}
				}
			}

			if (bcancel)//batalkan scan
				goto cancel;

			dwStart += queryRequest.info.RegionSize;
		} else {
			if ((DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize > 0)
				dwStart = (DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize;
		}

		if (dwStart > dwEnd)
		{
			timer = false;
			FinishFirstScan();
			SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                    Status : Finish!");
			ExitThread(0);
		}
		Sleep(10);
	}

cancel:
	EnableWindow(GetDlgItem(hDlgProc, IDC_BTNNEXTSCAN), TRUE);
	timer = false;
	SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                   Status : Cancel!");
	ExitThread(0);
}

//----------------------------------------------------------------------------------------------------------------------

void _fastcall ScanText(DWORD dwStart, DWORD dwEnd, char *text)
{
	ULONG BytesReaded = NULL;
	char val[1024];
	char tempBuffer[256] = { 0 };

	std::basic_string<char> temp_string;
	std::basic_string<wchar_t> temp_unicode_string;

	bcancel = false;
	timer = true;

	while (1)
	{
		if (bcancel)//batalkan scan
			goto cancel;


		if (CURRENT_PROCESS_ID == 0) {
			MessageBoxA(0, "Process Id is zero cannot do search click Change Process", "Information", MB_ICONINFORMATION);
			goto cancel;
		}

		VIRTUAL_QUERY_REQUEST queryRequest;
		ZeroMemory(&queryRequest, sizeof(VIRTUAL_QUERY_REQUEST));

		queryRequest.ProcessId = CURRENT_PROCESS_ID;
		queryRequest.Address = dwStart;

		if (!Driver.VirtualQueryInfo(&queryRequest))
			goto cancel;

		if (queryRequest.info.State & MEM_COMMIT && queryRequest.info.Protect & WRITABLE)
		{
			sprintf(tempBuffer, "Scanning: 0x%X\\0x%X", dwStart, queryRequest.info.RegionSize);
			SetDlgItemTextA(hDlgProc, IDC_SCANNING, tempBuffer);

			if (IsDlgButtonChecked(hDlgProc, IDC_FASTSCAN))
			{
				unsigned char* MEMORY = new unsigned char[queryRequest.info.RegionSize];
				Driver.ReadVirtualMemory<unsigned char>(CURRENT_PROCESS_ID, dwStart, queryRequest.info.RegionSize, MEMORY);

				for (DWORD i = 0; i <= (DWORD)queryRequest.info.RegionSize; i++)
				{
					if (bcancel)//batalkan scan
						goto cancel;

					BOOLEAN isUnicode = IsDlgButtonChecked(hDlgProc, IDC_SCANSTRINGUNICODE);

					if (isUnicode) {
						//Convert from ASCII to Unicode.
						wchar_t *unicode_check_string = new wchar_t[4046];
						mbstowcs(unicode_check_string, (const char*)&MEMORY[i], strlen(text) * 2);
						//Convert from Unicode to ASCII.
						char *str = new char[4046];
						wcstombs(str, unicode_check_string, wcslen(unicode_check_string));

						if (strcmp(str, text) == 0)
						{
							sprintf_s(val, "%08X      %s", (dwStart + i), text);
							SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
							i += strlen(text) + 1;
						}
						delete[] unicode_check_string;
						delete[] str;
					} else {
						if (strcmp((const char*)&MEMORY[i], text) == 0)
						{
							sprintf_s(val, "%08X      %s", (dwStart + i), text);
							SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
							i += strlen(text) + 1;
						}
					}
				}
				delete[] MEMORY;
			} else {
				for (DWORD i = dwStart; i <= (DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize; i++)
				{
					if (bcancel)//batalkan scan
						goto cancel;

					BOOLEAN isUnicode = IsDlgButtonChecked(hDlgProc, IDC_SCANSTRINGUNICODE);

					if (isUnicode) {
						temp_unicode_string = Driver.ReadString<wchar_t>(CURRENT_PROCESS_ID, i, strlen(text) * 2);

						char *str = new char[4046];
						wcstombs(str, temp_unicode_string.c_str(), wcslen(temp_unicode_string.c_str()));

						if (strcmp(str, text) == 0)
						{
							sprintf_s(val, "%08X      %s", i, text);
							SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
							i += strlen(text) + 1;
						}

						delete[] str;
					} else {
						temp_string = Driver.ReadString<char>(CURRENT_PROCESS_ID, i, strlen(text));

						if (strcmp(temp_string.c_str(), text) == 0)
						{
							sprintf_s(val, "%08X      %s", i, text);
							SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
							i += strlen(text) + 1;
						}
					}
				}
			}

			if (bcancel)//batalkan scan
				goto cancel;

			dwStart += queryRequest.info.RegionSize;
		} else {
			if((DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize > 0)
				dwStart = (DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize;
		}

		if (dwStart > dwEnd)
		{
			timer = false;
			FinishFirstScan();
			SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                    Status : Finish!");
			ExitThread(0);
		}
	}

cancel:
	EnableWindow(GetDlgItem(hDlgProc, IDC_BTNNEXTSCAN), TRUE);
	timer = false;
	SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                   Status : Cancel!");
	ExitThread(0);
}

//----------------------------------------------------------------------------------------------------------------------

void _fastcall ScanArrayOfByte(DWORD dwStart, DWORD dwEnd, char *ArrayOfByte)
{
	char val[1024];
	const char* pat = ArrayOfByte;
	DWORD firstMatch = NULL;
	BYTE bCur = NULL;
	char tempBuffer[256] = { 0 };

	bcancel = false;
	timer = true;

	while (1)
	{
		if (bcancel)//batalkan scan
			goto cancel;

		VIRTUAL_QUERY_REQUEST queryRequest;
		ZeroMemory(&queryRequest, sizeof(VIRTUAL_QUERY_REQUEST));

		queryRequest.ProcessId = CURRENT_PROCESS_ID;
		queryRequest.Address = dwStart;

		if (!Driver.VirtualQueryInfo(&queryRequest))
			goto cancel;

		if (queryRequest.info.State & MEM_COMMIT && queryRequest.info.Protect & WRITABLE)
		{

			sprintf(tempBuffer, "Scanning: 0x%X\\0x%X", dwStart, queryRequest.info.RegionSize);
			SetDlgItemTextA(hDlgProc, IDC_SCANNING, tempBuffer);

			if (IsDlgButtonChecked(hDlgProc, IDC_FASTSCAN))
			{
				unsigned char* MEMORY = new unsigned char[queryRequest.info.RegionSize];
				Driver.ReadVirtualMemory<unsigned char>(CURRENT_PROCESS_ID, dwStart, queryRequest.info.RegionSize, MEMORY);

				for (DWORD i = 0; i <= (DWORD)queryRequest.info.RegionSize; i++)
				{
					if (bcancel)//batalkan scan
						goto cancel;

					if (!*pat)
					{
						sprintf_s(val, "%08X      %s", firstMatch, ArrayOfByte);
						SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
						i += strlen(ArrayOfByte) + 1;
					}

					bCur = *(PBYTE)(&MEMORY[i]);

					if (*(PBYTE)pat == '\?' || bCur == getByte(pat))
					{
						if (!firstMatch)
							firstMatch = (dwStart + i);
						if (!pat[2])
						{
							sprintf_s(val, "%08X      %s", firstMatch, ArrayOfByte);
							SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
							i += strlen(ArrayOfByte) + 1;
						}

						if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
							pat += 3;
						else 
							pat += 2;
					}
					else
					{
						pat = ArrayOfByte;
						firstMatch = 0;
					}
				}

			} else {
				for (DWORD i = dwStart; i <= (DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize; i++)
				{
					if (bcancel)//batalkan scan
						goto cancel;

					if (!*pat)
					{
						sprintf_s(val, "%08X      %s", firstMatch, ArrayOfByte);
						SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
						i += strlen(ArrayOfByte) + 1;
					}

					bCur = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, i, 1);

					if (*(PBYTE)pat == '\?' || bCur == getByte(pat))
					{
						if (!firstMatch)
							firstMatch = i;
						if (!pat[2])
						{
							sprintf_s(val, "%08X      %s", firstMatch, ArrayOfByte);
							SendDlgItemMessageA(hDlgProc, IDC_LIST1, LB_ADDSTRING, 0, (LPARAM)val);
							i += strlen(ArrayOfByte) + 1;
						}

						if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
							pat += 3;
						else 
							pat += 2;
					}
					else
					{
						pat = ArrayOfByte;
						firstMatch = 0;
					}
				}
			}

			if (bcancel)//batalkan scan
				goto cancel;

			dwStart += queryRequest.info.RegionSize;
		} else {
			if((DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize > 0)
				dwStart = (DWORD)queryRequest.info.BaseAddress + queryRequest.info.RegionSize;
		}

		if (dwStart > dwEnd)
		{
			timer = false;
			FinishFirstScan();
			SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                    Status : Finish!");
			ExitThread(0);
		}
	}

cancel:
	EnableWindow(GetDlgItem(hDlgProc, IDC_BTNNEXTSCAN), TRUE);
	timer = false;
	SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                   Status : Cancel!");
	ExitThread(0);
}

//----------------------------------------------------------------------------------------------------------------------

void _fastcall ElapsedScan()
{
	int i = 0;
	char buf[100];
	timer = true;

	while (1)
	{
		if (!timer)
			ExitThread(0);

		sprintf_s(buf, "Elapsed Scan (second) : %d", i);
		SetDlgItemTextA(hDlgProc, IDC_ELAPSEDSCAN, buf);
		i++;

		Sleep(900);
	}
}

//----------------------------------------------------------------------------------------------------------------------

DWORD type = NULL;

void tScan()
{
	char chValue[255], chType[20], chStart[20], chEnd[20];

	EnableWindow(GetDlgItem(hDlgProc, IDC_BTNNEXTSCAN), FALSE);
	SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :           Status : Scanning ...");
	type = 1;

	//dapatkan string pada component
	GetDlgItemTextA(hDlgProc, IDC_EDVALUE, chValue, 11);
	GetDlgItemTextA(hDlgProc, IDC_CBXTYPE, chType, 19);
	GetDlgItemTextA(hDlgProc, IDC_EDSTARTADDR, chStart, 9);
	GetDlgItemTextA(hDlgProc, IDC_EDENDADDR, chEnd, 9);

	DWORD Start = hextoint(chStart);
	DWORD End = hextoint(chEnd);

	//jika string sama
	if (strcmp(chType, "Byte") == 0)
		type = 1;
	else if (strcmp(chType, "2 Byte") == 0)
		type = 2;
	else if (strcmp(chType, "4 Byte") == 0)
		type = 4;

	if (strcmp(chType, "Text") == 0)
		ScanText(Start, End, chValue);
	else if (strcmp(chType, "Array Of Byte") == 0)
		ScanArrayOfByte(Start, End, chValue);
	else Scan(Start, End, str2int(chValue), type);
}

//----------------------------------------------------------------------------------------------------------------------

void NextScan(int iCase)
{
	char buf[20], textBuffer[1024], tempval[1024];
	std::basic_string<char> temp;
	std::basic_string<wchar_t> unicode_string_temp;
	DWORD dwtemp = NULL;
	string stemp;
	ULONG BytesReaded = NULL;
	BOOLEAN isUnicode = FALSE;

	//dapatkan string pada component
	GetDlgItemTextA(hDlgProc, IDC_EDVALUE, buf, 11);
	const char* pat = buf;
	DWORD firstMatch = NULL;
	BYTE bCur = NULL;
	int j = 0;

	HWND hWndList1 = GetDlgItem(hDlgProc, IDC_LIST1);
	_ASSERTE(hWndList1 != NULL);
	int itemCount = (int)SendMessage(hWndList1, LB_GETCOUNT, (WPARAM)0, (LPARAM)0);
	if (itemCount != LB_ERR)
	{
		for (int i = 0; i < itemCount; i++)
		{
			SendMessageA(hWndList1, LB_GETTEXT, (WPARAM)i, (LPARAM)textBuffer);
			textBuffer[9] = '\0';
			UINT addr = hextoint(textBuffer);//berisi value dari listbox di konversi ke numeric

			switch (iCase)
			{
			case 0: //BYTE, WORD, DWORD
				dwtemp = Driver.ReadVirtualMemory<DWORD>(CURRENT_PROCESS_ID, addr, type);
				if (dwtemp == str2int(buf))
				{
					sprintf_s(tempval, "%08X      %d", addr, dwtemp);
					SendDlgItemMessageA(hDlgProc, IDC_LIST2, LB_ADDSTRING, 0, (LPARAM)tempval);
				}
				break;

			case 1: //TEXT
				isUnicode = IsDlgButtonChecked(hDlgProc, IDC_SCANSTRINGUNICODE);
				printf("is unicode = %d\n", isUnicode);
				if (isUnicode) {
					unicode_string_temp = Driver.ReadString<wchar_t>(CURRENT_PROCESS_ID, addr, strlen(buf) + 1);

					char *str = new char[4046];
					wcstombs(str, unicode_string_temp.c_str(), wcslen(unicode_string_temp.c_str()));

					if ((sizeof(str) / sizeof(*str)) > strlen(buf))
						str[strlen(buf)] = '\0';

					if (strcmp(str, buf) == 0)
					{
						sprintf_s(tempval, "%08X      %s", addr, buf);
						SendDlgItemMessageA(hDlgProc, IDC_LIST2, LB_ADDSTRING, 0, (LPARAM)tempval);
					}

					delete[] str;
				} else {
					temp = Driver.ReadString<char>(CURRENT_PROCESS_ID, addr, strlen(buf) + 1);

					if (temp.length() > strlen(buf))
						temp[strlen(buf)] = '\0';

					if (strcmp(temp.c_str(), buf) == 0)
					{
						sprintf_s(tempval, "%08X      %s", addr, buf);
						SendDlgItemMessageA(hDlgProc, IDC_LIST2, LB_ADDSTRING, 0, (LPARAM)tempval);
					}
				}
				break;

			case 2: //ARRAY OF BYTE
				j = 0;
				firstMatch = 0;
				pat = buf;

				while (*pat)
				{
					if (!*pat) {
						sprintf_s(tempval, "%08X      %s", firstMatch, buf);
						SendDlgItemMessageA(hDlgProc, IDC_LIST2, LB_ADDSTRING, 0, (LPARAM)tempval);
						break;
					}

					bCur = Driver.ReadVirtualMemory<BYTE>(CURRENT_PROCESS_ID, addr + j, 1);

					if (*(PBYTE)pat == '\?' || bCur == getByte(pat))
					{
						if (!firstMatch)
							firstMatch = (addr + j);
						if (!pat[2])
						{
							sprintf_s(tempval, "%08X      %s", firstMatch, buf);
							SendDlgItemMessageA(hDlgProc, IDC_LIST2, LB_ADDSTRING, 0, (LPARAM)tempval);
							break;
						}

						if (*(PWORD)pat == '\?\?' || *(PBYTE)pat != '\?')
							pat += 3;
						else 
							pat += 2;
						j++;
					} else {
						pat = buf;
						firstMatch = 0;
						j = 0;
						break;
					}
				}
				break;
			}
		}

		SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :                    Status : Finish!");
		timer = false;
		FinishNextScan();
	}
}

//----------------------------------------------------------------------------------------------------------------------

void tNextScan()
{
	char chType[20];
	GetDlgItemTextA(hDlgProc, IDC_CBXTYPE, chType, 19);
	SetDlgItemTextA(hDlgProc, IDC_RESULT, "Result :           Status : Scanning ...");

	if ((strcmp(chType, "Byte") == 0) ||
		(strcmp(chType, "2 Byte") == 0) ||
		(strcmp(chType, "4 Byte") == 0))
		NextScan(0);
	else if (strcmp(chType, "Text") == 0)
		NextScan(1);
	else if (strcmp(chType, "Array Of Byte") == 0)
		NextScan(2);
}
