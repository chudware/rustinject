#pragma once

#include <Windows.h>

typedef HINSTANCE(WINAPI* f_LoadLibraryA)(const char* lpLibFilename);
typedef FARPROC(WINAPI* f_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef BOOL(WINAPI* f_DLL_ENTRY_POINT)(void* hDll, DWORD dwReason, void* pReserved);

#ifdef _WIN64
typedef BOOL(WINAPI* f_RtlAddFunctionTable)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif

typedef struct MANUAL_MAPPING_DATA
{
	f_LoadLibraryA pLoadLibraryA;
	f_GetProcAddress pGetProcAddress;
#ifdef _WIN64
	f_RtlAddFunctionTable pRtlAddFunctionTable;
#endif
	BYTE* pbase;
	HINSTANCE hMod;
	DWORD fdwReasonParam;
	LPVOID reservedParam;
	BOOL SEHSupport;

#ifdef _WIN64
	void* pCxxThrowStub;
#endif
} MANUAL_MAPPING_DATA;

#ifdef __cplusplus
extern "C" {
#endif

void __stdcall Shellcode(MANUAL_MAPPING_DATA* pData);
void shellcode_end(void);

#ifdef __cplusplus
}
#endif
