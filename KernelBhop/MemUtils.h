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

#define INRANGE(x, a, b)	(x >= a && x <= b) 
#define getBits(x)			(INRANGE((x&(~0x20)), 'A', 'F') ? ((x&(~0x20)) - 'A' + 0x0A) : (INRANGE(x, '0', '9') ? x - '0' : 0))
#define getByte(x)			(getBits(x[0]) << 4 | getBits(x[1]))

using namespace std;
//----------------------------------------------------------------------------------------------------------------------

string IntToStr(int n);
string IntToHex(int n);
unsigned int hextoint(string s);
unsigned int str2int(char *s);
void ODS(const char *format, ...);