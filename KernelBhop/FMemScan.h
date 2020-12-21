#include "FEditAddress.h"
#include "FMemViewer.h"
#include "SpeedHack.h"

#define _DONATE_	TRUE
//----------------------------------------------------------------------------------------------------------------------

LRESULT CALLBACK DialogProc(HWND hDlg, UINT Msg, WPARAM wParam, LPARAM lParam)
{
	hDlgProc = hDlg;

	switch(Msg)
	{
		case WM_INITDIALOG:
			DialogUtils.SetFont(hDlg, lf, hFont, hDC, IDC_BTNDONATE, L"Lucida Console", 11, true);

			//add list combobox
			SetDlgItemTextA(hDlg, IDC_EDSTARTADDR, "00400000");
			SetDlgItemTextA(hDlg, IDC_EDENDADDR, "1F000000");
			SetDlgItemTextA(hDlg, IDC_EDSPEEDHACK, "1");
			//SendMessage(GetDlgItem(hDlg, IDC_FASTSCAN), BM_SETCHECK, 1, (LPARAM)0); //checked checkbox by default.
			SendDlgItemMessageA(hDlg, IDC_FASTSCAN, BM_SETCHECK, 1, (LPARAM)0);  //checked checkbox by default.
			SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_ADDSTRING, 0, (LPARAM)"Byte");
			SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_ADDSTRING, 0, (LPARAM)"2 Byte");
			SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_ADDSTRING, 0, (LPARAM)"4 Byte");
			SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_ADDSTRING, 0, (LPARAM)"Text");
			SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_ADDSTRING, 0, (LPARAM)"Array Of Byte");
			SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_SETCURSEL, 0, 0);
			EnableWindow(GetDlgItem(hDlg, IDC_BTNNEXTSCAN), FALSE);
			break;

		case WM_CLOSE:
			ExitProcess(0);
			EndDialog(hDlg, 0);
			break;

		case WM_COMMAND:
			switch(LOWORD(wParam))
			{
				case IDC_BTNSCAN:
					{
#if !_DONATE_
						int iTypeScan = (int)SendDlgItemMessageA(hDlg, IDC_CBXTYPE, CB_GETCURSEL, 0, 0);
						if(iTypeScan == 4)
						{
							MessageBoxA(0, "To use this feature, please donate first", "Information", MB_ICONINFORMATION);

							break;
						}
#endif
						//Scan
						char buf[10];
						GetDlgItemTextA(hDlg, IDC_BTNSCAN, buf, 10);

						if(!strcmp(buf, "Scan"))//jika text button = scan
						{
							SendDlgItemMessageA(hDlg, IDC_LIST2, LB_RESETCONTENT, 0, 0);
							SendDlgItemMessageA(hDlg, IDC_LIST1, LB_RESETCONTENT, 0, 0);
							CreateThread(0, 0, (LPTHREAD_START_ROUTINE)tScan, 0, 0, 0);
							CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ElapsedScan, 0, 0, 0);
							SetDlgItemTextA(hDlg, IDC_BTNSCAN, "New Scan");
							SetDlgItemTextA(hDlg, IDC_SCANNING, "Scanning: Nothing");
							EnableWindow(GetDlgItem(hDlg, IDC_BTNNEXTSCAN), TRUE);
							EnableWindow(GetDlgItem(hDlg, IDC_CBXTYPE), FALSE);
						}else
						{
							bcancel = true;//buat cancel scan
							SendDlgItemMessageA(hDlg, IDC_LIST1, LB_RESETCONTENT, 0, 0);
							SendDlgItemMessageA(hDlg, IDC_LIST2, LB_RESETCONTENT, 0, 0);
							SetDlgItemTextA(hDlg, IDC_FOUND, "Found : 0");
							SetDlgItemTextA(hDlg, IDC_ELAPSEDSCAN, "Elapsed Scan (second) : 0");
							SetDlgItemTextA(hDlg, IDC_SCANNING, "Scanning: Nothing");
							SetDlgItemTextA(hDlg, IDC_BTNSCAN, "Scan");
							EnableWindow(GetDlgItem(hDlg, IDC_BTNNEXTSCAN), FALSE);
							EnableWindow(GetDlgItem(hDlg, IDC_CBXTYPE), TRUE);
						}
					}
					break;

				case IDC_BTNNEXTSCAN:
					{
						EnableWindow(GetDlgItem(hDlg, IDC_BTNNEXTSCAN), FALSE);
						SendDlgItemMessage(hDlg, IDC_LIST2, LB_RESETCONTENT, 0, 0);
						CreateThread(0, 0, (LPTHREAD_START_ROUTINE)tNextScan, 0, 0, 0);
						CreateThread(0, 0, (LPTHREAD_START_ROUTINE)ElapsedScan, 0, 0, 0);
					}
					break;
				case IDC_CBXTYPE:
					//Change of ComboBox for type of scan
					if (HIWORD(wParam) == CBN_SELCHANGE) {
						char buf[100];
						GetDlgItemTextA(hDlg, IDC_CBXTYPE, buf, 100);
						if (strcmp(buf, "Text") == 0)
							ShowWindow(GetDlgItem(hDlg, IDC_SCANSTRINGUNICODE), SW_SHOW);
						else
							ShowWindow(GetDlgItem(hDlg, IDC_SCANSTRINGUNICODE), SW_HIDE);
					}
					break;
				case IDC_BTNPRINTMEM:
					DialogBoxParamA(hCurrentModule, MAKEINTRESOURCEA(IDD_DIALOG2), NULL, DLGPROC(MemViewer), NULL);
					break;

				case IDC_BTNADDRLIST:
					DialogBoxParamA(hCurrentModule, MAKEINTRESOURCEA(IDD_DIALOG4), NULL, DLGPROC(EditAddress), NULL);
					break;

				case IDC_LIST1:
					{
						// Get current selection index in listbox
						int itemIndex = (int)SendDlgItemMessageA(hDlg, IDC_LIST1, LB_GETCURSEL, (WPARAM)0, (LPARAM) 0);
						if (itemIndex != LB_ERR)
						{
							// Get length of text in listbox
							int textLen = (int)SendDlgItemMessageA(hDlg, IDC_LIST1, LB_GETTEXTLEN, (WPARAM)itemIndex, 0);
							// Allocate buffer to store text (consider +1 for end of string)
							char *textBuffer = new char[textLen + 1];
							// Get actual text in buffer
							SendDlgItemMessageA(hDlg, IDC_LIST1, LB_GETTEXT, (WPARAM)itemIndex, (LPARAM)textBuffer);
							// set to textbox
							SetDlgItemTextA(hDlg, IDC_EDADDRSEL, textBuffer);
							// Free text
							delete []textBuffer;
							// Avoid dangling references
							textBuffer = NULL;
						}
					}
					break;

				case IDC_LIST2:
				{
					// Get current selection index in listbox
					int itemIndex = (int)SendDlgItemMessageA(hDlg, IDC_LIST2, LB_GETCURSEL, (WPARAM)0, (LPARAM) 0);
					if (itemIndex != LB_ERR)
					{
						// Get length of text in listbox
						int textLen = (int)SendDlgItemMessageA(hDlg, IDC_LIST2, LB_GETTEXTLEN, (WPARAM)itemIndex, 0);
						// Allocate buffer to store text (consider +1 for end of string)
						char *textBuffer = new char[textLen + 1];
						// Get actual text in buffer
						SendDlgItemMessageA(hDlg, IDC_LIST2, LB_GETTEXT, (WPARAM)itemIndex, (LPARAM)textBuffer);
						// set to textbox
						SetDlgItemTextA(hDlg, IDC_EDADDRSEL, textBuffer);
						// Free text
						delete []textBuffer;
						// Avoid dangling references
						textBuffer = NULL;
					}
				}
				break;

				case IDC_BTNCOPY:
					{
						char txtbuf[10];
						HWND hwnd = GetDesktopWindow();
						GetDlgItemTextA(hDlg, IDC_EDADDRSEL, txtbuf, 9);
						DialogUtils.ToClipboard(hwnd, txtbuf);
					}
					break;

				case IDC_BTNDONATE:
					{
					MessageBoxA(0, "Contact me on Discord: HighGamer.com#8990\n"
							"If you want to donate to me you can donate a link will open up\n", "Information", MB_ICONINFORMATION);
						ShellExecuteA(NULL, "Open", "https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=WM3VGGYKE5MD8", NULL, NULL, SW_SHOWNORMAL);
					}
					break;

				case IDC_CHKSPEEDHACK:
					{
						if(IsDlgButtonChecked(hDlg, IDC_CHKSPEEDHACK))
						{
#if !_DONATE_
							MessageBoxA(0, "To use this feature, please donate first", "Information", MB_ICONINFORMATION);
							break;
#endif

							//TODO fix this with Driver method possibly -HighGamer
							char buff[4];
							GetDlgItemTextA(hDlg, IDC_EDSPEEDHACK, buff, 3);
							//SpeedHack::SpeedHack(true);
							//SpeedHack::SetSpeed((float)atoi(buff));
							EnableWindow(GetDlgItem(hDlg, IDC_EDSPEEDHACK), FALSE);
						}
						else
						{
							//SpeedHack::SpeedHack(false);
							EnableWindow(GetDlgItem(hDlg, IDC_EDSPEEDHACK), TRUE); 
						}
					}
					break;
				case IDC_CHANGEPROCESSNAME:
					GetDlgItemTextW(hDlg, IDC_PROCESSNAME, CURRENT_PROCESS_NAME, MAX_PATH);
					// Get address of client.dll & pid of csgo from our driver
					CURRENT_PROCESS_ID = Driver.GetTargetProcessId(CURRENT_PROCESS_NAME);
					printf("Process ID set to = %d [0x%X]\n", CURRENT_PROCESS_ID, CURRENT_PROCESS_ID);
					char buff[MAX_PATH];
					sprintf(buff, "%llu", CURRENT_PROCESS_ID);
					SetDlgItemTextA(hDlg, IDC_PROCESSID, buff);
					break;
				case IDC_PROCESSID:
					//Text box changed (process id box change), update the CURRENT_PROCESS_ID.
					if (HIWORD(wParam) == EN_CHANGE) {
						char buff[MAX_PATH];
						GetDlgItemTextA(hDlg, IDC_PROCESSID, buff, MAX_PATH);
						CURRENT_PROCESS_ID = str2int(buff);
						printf("Process ID changed to = %d [0x%X]\n", CURRENT_PROCESS_ID, CURRENT_PROCESS_ID);
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