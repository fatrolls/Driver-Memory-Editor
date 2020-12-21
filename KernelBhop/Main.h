#pragma once

#include <Windows.h>
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

#ifndef KE_INTERFACE_INCLUDED
#define KE_INTERFACE_INCLUDED
	#include "KeInterface.h"
#endif

extern DWORD CURRENT_PROCESS_ID;
extern WCHAR CURRENT_PROCESS_NAME[MAX_PATH + 1];
extern KeInterface Driver;