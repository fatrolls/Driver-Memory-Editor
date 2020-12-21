#include <windows.h>
#include <tlhelp32.h>
#include <sstream>
#include <fstream>
#include <iostream>

using namespace std;

#define PROP_ORIGINAL_FONT		TEXT("_Hyperlink_Original_Font_")
#define PROP_ORIGINAL_PROC		TEXT("_Hyperlink_Original_Proc_")
#define PROP_STATIC_HYPERLINK	TEXT("_Hyperlink_From_Static_")
#define PROP_UNDERLINE_FONT		TEXT("_Hyperlink_Underline_Font_")
//----------------------------------------------------------------------------------------------------------------------

class CDialogUtils
{
public:
	void SetFont(HWND &hDlg, LOGFONT &lf, HFONT &hFont, HDC &hDC, int nIDDlgItem, const TCHAR *cchFontName, int nPoint = 12, bool isBold = false);
	BOOL ConvertStaticToHyperlink(HWND hWndCtl);
	BOOL ConvertStaticToHyperlink(HWND hWndParent, UINT uiCtlId);
	void ToClipboard(HWND hWnd, const std::string &s);
};
