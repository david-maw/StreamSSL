#pragma once
// General purpose utilities for use both at compile time and run time
#define Stringize(L) #L
#define MakeString(M, L) M(L)
#define $Line					\
	MakeString(Stringize, __LINE__)
#define Reminder				\
	__FILE__ "(" $Line ") : Reminder: "
// usage #pragma message(Reminder "your message here")

// Handy structure to store version information
struct VersionInfo
{
    VersionInfo() : Major(0), Minor(0), BuildNum(0) {}
    unsigned int Major;
    unsigned int Minor;
    unsigned int BuildNum;
};
bool GetWindowsVersion(VersionInfo& info);
bool IsWindows11OrGreater();
std::wstring string_format(const WCHAR* pszFormat, ...);
std::wstring WinErrorMsg(int nErrorCode);
void PrintHexDump(const void *const buf, size_t length);
void PrintHexDump(size_t length, const void * const buf);
void PrintFullHexDump(size_t length, const void * const buf);
void SetThreadName(std::string const &threadName);
void SetThreadName(std::string const &threadName, DWORD dwThreadID);
void DebugBeginMsg();
void DebugBeginMsg(const CHAR* pszFormat, ...);
void DebugContinueMsg(const CHAR* pszFormat, ...);
void DebugEndMsg();
void DebugEndMsg(const CHAR* pszFormat, ...);
void DebugMsg(const CHAR* pszFormat, ...);
void DebugMsg(const WCHAR* pszFormat, ...);
void DebugHresult(const char* msg, HRESULT hr);
void DebugHresult(const WCHAR* msg, HRESULT hr);
std::string HexDigits(const void* const buf, size_t len);
bool IsUserAdmin();
std::wstring GetHostName(COMPUTER_NAME_FORMAT WhichName = ComputerNameDnsHostname);
std::wstring GetCurrentUserName();
const char* const GetVersionText();
