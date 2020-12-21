#include "CDialogUtils.h"

ofstream infile;
//----------------------------------------------------------------------------------------------------------------------

LRESULT CALLBACK _HyperlinkParentProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC pfnOrigProc = (WNDPROC)GetProp(hWnd, PROP_ORIGINAL_PROC);

	switch(Message)
	{
		case WM_CTLCOLORSTATIC:
			{
				HDC hDC = (HDC)wParam;
				HWND hWndCtl = (HWND)lParam;

				BOOL fHyperlink = (GetProp(hWndCtl, PROP_STATIC_HYPERLINK) != NULL);
				if(fHyperlink)
				{
					LRESULT lr = CallWindowProc(pfnOrigProc, hWnd, Message, wParam, lParam);
					SetTextColor(hDC, RGB(0, 0, 192));

					return lr;
				}
			}
			break;

		case WM_DESTROY:
			{
				SetWindowLong(hWnd, GWLP_WNDPROC, (LONG)pfnOrigProc);
				RemoveProp(hWnd, PROP_ORIGINAL_PROC);
			}
			break;
	}

	return CallWindowProc(pfnOrigProc, hWnd, Message, wParam, lParam);
}

LRESULT CALLBACK _HyperlinkProc(HWND hWnd, UINT Message, WPARAM wParam, LPARAM lParam)
{
	WNDPROC pfnOrigProc = (WNDPROC)GetProp(hWnd, PROP_ORIGINAL_PROC);

	switch(Message)
	{
		case WM_DESTROY:
			{
				SetWindowLong(hWnd, GWLP_WNDPROC, (LONG)pfnOrigProc);
				RemoveProp(hWnd, PROP_ORIGINAL_PROC);

				HFONT hOrigFont = (HFONT)GetProp(hWnd, PROP_ORIGINAL_FONT);
				SendMessage(hWnd, WM_SETFONT, (WPARAM)hOrigFont, 0);
				RemoveProp(hWnd, PROP_ORIGINAL_FONT);

				HFONT hFont = (HFONT)GetProp(hWnd, PROP_UNDERLINE_FONT);
				DeleteObject(hFont);
				RemoveProp(hWnd, PROP_UNDERLINE_FONT);
				RemoveProp(hWnd, PROP_STATIC_HYPERLINK);
			}
			break;

		case WM_MOUSEMOVE:
			{
				if(GetCapture() != hWnd)
				{
					HFONT hFont = (HFONT)GetProp(hWnd, PROP_UNDERLINE_FONT);
					SendMessage(hWnd, WM_SETFONT, (WPARAM)hFont, FALSE);
					InvalidateRect(hWnd, NULL, FALSE);
					SetCapture(hWnd);
				}
				else
				{
					RECT rect;
					GetWindowRect(hWnd, &rect);

					POINT pt = {LOWORD(lParam), HIWORD(lParam)};
					ClientToScreen(hWnd, &pt);

					if(!PtInRect(&rect, pt))
					{
						HFONT hFont = (HFONT)GetProp(hWnd, PROP_ORIGINAL_FONT);
						SendMessage(hWnd, WM_SETFONT, (WPARAM)hFont, FALSE);
						InvalidateRect(hWnd, NULL, FALSE);
						ReleaseCapture();
					}
				}
			}
			break;

		case WM_SETCURSOR:
			{
				// Since IDC_HAND is not available on all operating systems,
				// we will load the arrow cursor if IDC_HAND is not present.
				HCURSOR hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_HAND));
				if(NULL == hCursor)
					hCursor = LoadCursor(NULL, MAKEINTRESOURCE(IDC_ARROW));

				SetCursor(hCursor);

				return TRUE;
			}
	}

	return CallWindowProc(pfnOrigProc, hWnd, Message, wParam, lParam);
}

//----------------------------------------------------------------------------------------------------------------------

void CDialogUtils::SetFont(HWND &hDlg, LOGFONT &lf, HFONT &hFont, HDC &hDC, int nIDDlgItem, const TCHAR *cchFontName, int nPoint, bool isBold)
{
	hDC = GetDC(NULL);

	lf.lfHeight = MulDiv(nPoint, GetDeviceCaps(hDC, LOGPIXELSY), 72);
	lf.lfWeight = (isBold) ? FW_BOLD : FW_NORMAL;

	ReleaseDC(NULL, hDC);

	lstrcpy(lf.lfFaceName, cchFontName);
	hFont = CreateFontIndirect (&lf);
	SendDlgItemMessage(hDlg, nIDDlgItem, WM_SETFONT, (WPARAM)hFont, 0);
}

BOOL CDialogUtils::ConvertStaticToHyperlink(HWND hWndCtl)
{
	// Subclass the parent so we can color the controls as we desire.
	HWND hWndParent = GetParent(hWndCtl);
	if(NULL != hWndParent)
	{
		WNDPROC pfnOrigProc = (WNDPROC)GetWindowLong(hWndParent, GWLP_WNDPROC);
		if(pfnOrigProc != _HyperlinkParentProc)
		{
			SetProp(hWndParent, PROP_ORIGINAL_PROC, (HANDLE)pfnOrigProc);
			SetWindowLong(hWndParent, GWLP_WNDPROC, (LONG)(WNDPROC)_HyperlinkParentProc);
		}
	}

	// Make sure the control will send notifications.
	DWORD dwStyle = GetWindowLong(hWndCtl, GWL_STYLE);
	SetWindowLong(hWndCtl, GWL_STYLE, dwStyle | SS_NOTIFY);

	// Subclass the existing control.
	WNDPROC pfnOrigProc = (WNDPROC)GetWindowLong(hWndCtl, GWLP_WNDPROC);
	SetProp(hWndCtl, PROP_ORIGINAL_PROC, (HANDLE)pfnOrigProc);
	SetWindowLong(hWndCtl, GWLP_WNDPROC, (LONG)(WNDPROC)_HyperlinkProc);

	// Create an updated font by adding an underline.
	HFONT hOrigFont = (HFONT)SendMessage(hWndCtl, WM_GETFONT, 0, 0);
	SetProp(hWndCtl, PROP_ORIGINAL_FONT, (HANDLE)hOrigFont);

	LOGFONT lf;
	GetObject(hOrigFont, sizeof(lf), &lf);
	lf.lfUnderline = TRUE;
	//lf.lfWeight = FW_BOLD;

	HFONT hFont = CreateFontIndirect(&lf);
	SetProp(hWndCtl, PROP_UNDERLINE_FONT, (HANDLE)hFont);

	// Set a flag on the control so we know what color it should be.
	SetProp(hWndCtl, PROP_STATIC_HYPERLINK, (HANDLE)1);

	return TRUE;
}

BOOL CDialogUtils::ConvertStaticToHyperlink(HWND hWndParent, UINT uiCtlId)
{
	return ConvertStaticToHyperlink(GetDlgItem(hWndParent, uiCtlId));
}

void CDialogUtils::ToClipboard(HWND hWnd, const string &s)
{
	OpenClipboard(hWnd);
	EmptyClipboard();

	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, s.size() + 1);
	if(!hg)
	{
		CloseClipboard();

		return;
	}

	memcpy(GlobalLock(hg), s.c_str(), s.size()+1);
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();
	GlobalFree(hg);
}