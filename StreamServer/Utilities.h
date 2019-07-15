#pragma once
// General purpose utilities for use both at compile time and run time
#define Stringize(L) #L
#define MakeString(M, L) M(L)
#define $Line					\
	MakeString(Stringize, __LINE__)
#define Reminder				\
	__FILE__ "(" $Line ") : Reminder: "
// usage #pragma message(Reminder "your message here")

std::wstring string_format(const WCHAR* pszFormat, ...);
std::wstring WinErrorMsg(int nErrorCode);
void PrintHexDump(DWORD length, const void * const buf);
void PrintHexDump(DWORD length, const void * const buf, const bool verbose);
void SetThreadName(char* threadName);
void SetThreadName(char* threadName, DWORD dwThreadID);
void DebugMsg(const WCHAR* pszFormat, ...);
void DebugMsg(const CHAR* pszFormat, ...);
bool IsUserAdmin();
std::wstring GetHostName(COMPUTER_NAME_FORMAT WhichName = ComputerNameDnsHostname);
std::wstring GetUserName();
