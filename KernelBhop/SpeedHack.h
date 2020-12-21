#include <windows.h>

namespace SpeedHack
{
	/*
	bool SpeedHackEnabled, SpeedHackInitialized;
	int TickCount;
	__int64 PerformanceCount, PerformanceFrequency;
	float Acceleration = 1;
	 
	typedef MMRESULT (__stdcall *timebeginperiod) (UINT Period);
	timebeginperiod TimeBeginPeriod = (timebeginperiod)GetProcAddress(LoadLibraryA("winmm.dll"), "timeBeginPeriod");
	 
	typedef MMRESULT (__stdcall *timeendperiod) (UINT Period);
	timeendperiod TimeEndPeriod = (timeendperiod)GetProcAddress(LoadLibraryA("winmm.dll"), "timeEndPeriod");

	void Sleep_(int iMiliSecond)
	{
		TimeBeginPeriod(1);
		Sleep(iMiliSecond);
		TimeEndPeriod(1);
	}
	 
	void Tick()
	{
		SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
		const int SleepTime = 30;
	 
		while(true)
		{
			Sleep_(SleepTime);

			if(SpeedHackEnabled)
			{
				TickCount += (int)(SleepTime * Acceleration);
				PerformanceCount += (long long)((SleepTime * PerformanceFrequency / 1000) * Acceleration);
			}
			else
			{
				TickCount += SleepTime;
				PerformanceCount += (long long)(SleepTime * PerformanceFrequency / 1000);
			}
		}
	}
	 
	int __declspec(naked) NewTickCount()
	{
		__asm
		{
			mov eax, [TickCount];
			ret;
		}
	}
	 
	BOOL WINAPI NewQueryPerformanceCounter(LARGE_INTEGER* Count)
	{
		Count->QuadPart = PerformanceCount;

		return TRUE;
	}
	 
	void SetSpeed(float Speed)
	{
		Acceleration = Speed;
	}
	 
	void SpeedHack(bool Enable)
	{
		SpeedHackEnabled = Enable;

		if(Enable == true)
		{
			TickCount = GetTickCount();
			LARGE_INTEGER Ref;
			QueryPerformanceFrequency(&Ref);
			PerformanceFrequency = Ref.QuadPart;
	 
			QueryPerformanceCounter(&Ref);
			PerformanceCount = Ref.QuadPart;
	 
			if(SpeedHackInitialized == false)
			{
				CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)&Tick, NULL, 0, NULL);
	 
				DWORD dwGetTickCount = (DWORD)GetProcAddress(LoadLibraryA("kernel32.dll"), "GetTickCount");
				MemFunctions->DetourCreate((PBYTE)dwGetTickCount, (PBYTE)NewTickCount, 5);

				DWORD TimeGetTime = (DWORD)GetProcAddress(LoadLibraryA("winmm.dll"), "timeGetTime");
				MemFunctions->DetourCreate((PBYTE)TimeGetTime, (PBYTE)NewTickCount, 5);

				DWORD QueryPerformanceCounter = (DWORD)GetProcAddress(LoadLibraryA("kernel32.dll"), "QueryPerformanceCounter") + 6;
				MemFunctions->DetourCreate((PBYTE)QueryPerformanceCounter, (PBYTE)NewQueryPerformanceCounter, 5); //QueryPerformanceCounter does not seems to be really needed for MS but i did it anyway
				
				SpeedHackInitialized = true;
			}
		}
	}*/
}