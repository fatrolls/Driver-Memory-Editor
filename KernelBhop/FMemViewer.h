#include "FEditVal.h"

CDialogUtils DialogUtils;
CMemoryScanner MemoryScanner;

LOGFONT lf;
HFONT hFont = NULL;
HDC hDC = NULL;
char buf[100], buf2[100];

enum
{
	TIMER2
};

//----------------------------------------------------------------------------------------------------------

LRESULT CALLBACK MemViewer(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	//variable deklarasikan dulu
	hDlgMemViewer = hDlg;
	DWORD dwAddr;
	
	switch(Msg)
	{
		case WM_INITDIALOG:
			for(int i = IDC_BVAL1; i <= IDC_BVAL256; i++)
			{
				DialogUtils.SetFont(hDlg, lf, hFont, hDC, i, L"MS Hans Sherif", 11, false);
				DialogUtils.ConvertStaticToHyperlink(GetDlgItem(hDlg, i));
				if(i <= 15)
				{
					DialogUtils.SetFont(hDlg, lf, hFont, hDC, IDC_ADDR1 + i, L"MS Hans Sherif", 11, false);
					DialogUtils.SetFont(hDlg, lf, hFont, hDC, IDC_BCHAR1 + i, L"MS Hans Sherif", 11, false);
				}
			}

			SetDlgItemTextA(hDlg, IDC_EDADDR, "00400000");
			SetDlgItemTextA(hDlg, IDC_EDINTERVAL, "500");
			DialogUtils.SetFont(hDlg, lf, hFont, hDC, IDC_BTNDONATE, TEXT("Lucida Console"), 11, true);
			SetTimer(hDlg, TIMER2, 500, 0);
			break;

		case WM_CLOSE:
			EndDialog(hDlg, 0);
			break;

		case WM_TIMER:
			switch(LOWORD(lParam))
			{
				case TIMER2:
					{
						GetDlgItemTextA(hDlg, IDC_EDADDR, buf, 9);
						dwAddr = hextoint(buf);

						for(int i = 0; i <= 255; i++)
						{
							MemoryScanner.InitAddr(hDlg, IDC_BVAL1 + i, dwAddr, i);
							if(i <= 15)
								SetDlgItemTextA(hDlg, IDC_ADDR1 + i, IntToHex(dwAddr + (16 * i)).c_str());
						}

						//Init value ke char
						MemoryScanner.Value2Char(hDlg, IDC_BCHAR1, dwAddr);
					}
					break;
			}
			break;

		case WM_COMMAND:
			{
				for(int i = IDC_BVAL1; i <= IDC_BVAL256; i++)
				{
					if(LOWORD(wParam) == i)
					{
						//ambil text dari edaddress
						char buf[9];
						GetDlgItemTextA(hDlg, IDC_EDADDR, buf, 9);
						AddrEditValue = hextoint(buf) + i;
						IndexbVal = i;
						DialogBoxParamA(hCurrentModule, MAKEINTRESOURCEA(IDD_DIALOG3), NULL, DLGPROC(EditVal), NULL);
					}
				}

				switch(LOWORD(wParam))
				{
					case IDC_BTNINC:
						{
							GetDlgItemTextA(hDlg, IDC_EDADDR, buf, 9);
							DWORD X = hextoint(buf) + 16;
							SetDlgItemTextA(hDlg, IDC_EDADDR, IntToHex(X).c_str());
						}
						break;

					case IDC_BTNDEC:
						{
							GetDlgItemTextA(hDlg, IDC_EDADDR, buf, 9);
							DWORD X = hextoint(buf) - 16;
							SetDlgItemTextA(hDlg, IDC_EDADDR, IntToHex(X).c_str());
						}
						break;

					case IDC_BTNINC2:
						{
							GetDlgItemTextA(hDlg, IDC_EDADDR, buf, 9);
							DWORD X = hextoint(buf) + 0x100;
							SetDlgItemTextA(hDlg, IDC_EDADDR, IntToHex(X).c_str());
						}
						break;

					case IDC_BTNDEC2:
						{
							GetDlgItemTextA(hDlg, IDC_EDADDR, buf, 9);
							DWORD X = hextoint(buf) - 0x100;
							SetDlgItemTextA(hDlg, IDC_EDADDR, IntToHex(X).c_str());
						}
						break;

					case IDC_BTNGOTO:
						{
							GetDlgItemTextA(hDlg, IDC_EDMODULE, buf2, 100);
							DWORD dwModule = (DWORD)GetModuleHandleA(buf2);
							SetDlgItemTextA(hDlg, IDC_EDADDR, IntToHex(dwModule).c_str());
						}
						break;

					case IDC_BTNINTERVAL:
						{
							GetDlgItemTextA(hDlg, IDC_EDINTERVAL, buf2, 6);
							SetTimer(hDlg, TIMER2, str2int(buf2), 0);
						}
						break;

					case IDC_BTNWRITEABLE:
						{
							GetDlgItemTextA(hDlg, IDC_EDADDR, buf2, 9);

							PVOID pAddr = (PVOID)hextoint(buf2);
							DWORD pSize = 4;
							DWORD OldProtect = NULL;
							//MemFunctions->NtProtectVirtualMemory(GetCurrentProcess(), &pAddr, &pSize, PAGE_EXECUTE_READWRITE, &OldProtect);
							printf("bOldProtect = %X\n", OldProtect);
							PROTECT_VIRTUAL_MEMORY_REQUEST virtualMemoryRequest;
							ZeroMemory(&virtualMemoryRequest, sizeof(PROTECT_VIRTUAL_MEMORY_REQUEST));

							virtualMemoryRequest.ProcessId = CURRENT_PROCESS_ID;
							virtualMemoryRequest.Address = (DWORD)pAddr;
							virtualMemoryRequest.size = pSize;
							virtualMemoryRequest.NewAccessProtection = PAGE_EXECUTE_READWRITE;
							virtualMemoryRequest.OldAccessProtection = NULL;
							Driver.ProtectVirtualMemory(&virtualMemoryRequest);
							printf("aOldProtect = %X\n", virtualMemoryRequest.OldAccessProtection);
						}
						break;
				}
			}
			break;

		default:
			return FALSE;
			break;
	}

	return FALSE;
}