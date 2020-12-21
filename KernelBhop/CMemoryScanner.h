#pragma once

class CMemoryScanner
{
public:
	void InitAddr(HWND hDlg, int nIDDlgItem, DWORD dwAddr, DWORD dwOffs);
	void ShowValues(HWND hDlg, int nIDDlgItem, DWORD dwAddr, DWORD type, BOOLEAN isString, BOOLEAN isUnicode);
	void Value2Char(HWND hDlg, int nIDDlgItem, DWORD dwAddr);
	void EditMemory(DWORD dwAddress, BYTE bVal);
	void EditMemory(DWORD dwAddress, DWORD dwVal, DWORD type);
	void EditString(DWORD dwAddress, std::string strVal, BOOLEAN isUnicode);
};