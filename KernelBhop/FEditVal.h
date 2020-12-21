#include "MemScan.h"
#include "resource.h"

extern CMemoryScanner MemoryScanner;

//----------------------------------------------------------------------------------------------------------

HWND hDlgMemViewer = NULL;
HMODULE hCurrentModule = NULL;
DWORD AddrEditValue = NULL, IndexbVal = NULL;

LRESULT CALLBACK EditVal(HWND hDlg, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
	char buf[9];
	BYTE NewVal = NULL;

	switch(uMsg)
	{
		case WM_INITDIALOG:
			//set text editvalue dari text label printmemory yang di pilih
			GetDlgItemTextA(hDlgMemViewer, IndexbVal, buf, 3);
			NewVal = hextoint(buf);
			SetDlgItemTextA(hDlg, IDC_EDITVALUE, IntToStr(NewVal).c_str());
			break;

		case WM_CLOSE:
			EndDialog(hDlg, 0);
			break;

		case WM_COMMAND:
			switch(LOWORD(wParam))
			{
				case IDC_BTNEDITVALUE:
					{
						//edit value memory
						GetDlgItemTextA(hDlg, IDC_EDITVALUE, buf, 15);
						NewVal = str2int(buf);//konvert dari text ke int
						MemoryScanner.EditMemory(AddrEditValue, NewVal);
						EndDialog(hDlg, 0);
					}
					break;
			}
			break;

		default:
			return FALSE;
			break;
	}

	return FALSE;
}