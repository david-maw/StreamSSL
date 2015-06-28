#pragma once

#ifndef WINVER				
#define WINVER _WIN32_WINNT_VISTA  // Allow use of features specific to Windows 6 (Vista) or later
#endif

// Define a bool to check if this is a DEBUG or RELEASE build
#if defined(_DEBUG)
const bool debug = true;
#else
const bool debug = false;
#endif

#include <tchar.h>

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif

#define _AFXDLL
#include <afxwin.h>
#include <afxmt.h>

#include <iostream>

#define Stringize( L )			#L
#define MakeString( M, L )		M(L)
#define $Line					\
	MakeString(Stringize, __LINE__)
#define Reminder				\
	__FILE__ "(" $Line ") : Reminder: "
// usage #pragma message(Reminder "your message here")

void PrintHexDump(DWORD length, const void * const buf);
void PrintHexDump(DWORD length, const void * const buf, const bool verbose);
void SetThreadName(char* threadName);
void SetThreadName(char* threadName, DWORD dwThreadID);
void DebugMsg(const char* pszFormat, ...);
bool IsUserAdmin();