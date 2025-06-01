#include "Utilities.h"
#include "pch.h"

#include "Utilities.h"
#include "AppVersion.h"

#include <algorithm>
#include <memory>    // For std::unique_ptr
#include <string>

// General purpose functions

std::wstring& rtrim(std::wstring& str, const std::wstring& chars = L"\t\n\v\f\r ")
{
	str.erase(str.find_last_not_of(chars) + 1);
	return str;
}

std::wstring string_format(const WCHAR* pszFormat, ...) {
	int n = lstrlen(pszFormat) * 2; /* Reserve two times as much as the length of the fmt_str */
	if (n < 10) n = 10;
	std::unique_ptr<WCHAR[]> formatted;
	va_list ap;
	while (true) {
		formatted = std::make_unique<WCHAR[]>(n); /* Wrap the plain char array into the unique_ptr */
		wcscpy_s(&formatted[0], n, pszFormat);
		va_start(ap, pszFormat);
		const int final_n = _vsnwprintf_s(&formatted[0],n, n, pszFormat, ap);
		va_end(ap);
		if (final_n < 0 || final_n >= n)
			n += abs(final_n - n + 1);
		else
			break;
	}
	return std::wstring(formatted.get());
}
// Utility functions to handle Windows Versions
bool GetWindowsVersion(VersionInfo& info)
{
	// Thanks to https://www.codeproject.com/Articles/5336372/Windows-Version-Detection for this method
	auto sharedUserData = (BYTE*)0x7FFE0000;
	info.Major = *(ULONG*)(sharedUserData + 0x26c);
	info.Minor = *(ULONG*)(sharedUserData + 0x270);
	info.BuildNum = *(ULONG*)(sharedUserData + 0x260);
	return true;
}

bool IsWindows11OrGreater()
{
	VersionInfo info;
	return GetWindowsVersion(info) && (info.Major > 10 || (info.Major == 10 && info.BuildNum >= 22000));
}
// Utility function to get the hostname of the host I am running on
std::wstring GetHostName(COMPUTER_NAME_FORMAT WhichName)
{
	DWORD NameLength = 0;
	if (ERROR_SUCCESS == ::GetComputerNameEx(WhichName, nullptr, &NameLength))
	{
		std::wstring ComputerName;
		ComputerName.resize(NameLength);
		if (::GetComputerNameEx(WhichName, &ComputerName[0], &NameLength))
		{
			return ComputerName;
		}
	}
	return std::wstring();
}

// Utility function to return the user name I'm running under
std::wstring GetCurrentUserName()
{
	DWORD NameLength = 0;
	if (ERROR_SUCCESS == ::GetUserName(nullptr, &NameLength))
	{
		std::wstring UserName;
		UserName.resize(NameLength);
		if (::GetUserName(&UserName[0], &NameLength))
		{
			return UserName;
		}
	}
	return std::wstring();
}

std::wstring WinErrorMsg(int nErrorCode)
{
	std::wstring theMsg;
	constexpr int MaxMsgLen = 200;
	theMsg.resize(MaxMsgLen); // Reserve enough space to allow the message to fit inside the string
	try
	{
		auto len = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM,
			nullptr, nErrorCode,
			MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
			&theMsg[0],
			MaxMsgLen,
			nullptr);
		theMsg.resize(len);
		rtrim(theMsg);
		if (theMsg.empty())
			theMsg = string_format(L"Error code %u (0x%.8x)", nErrorCode, nErrorCode);
	}
	catch (...)
	{
	}
	return theMsg;
}

//
// Usage: SetThreadName ("MainThread"[, threadID]);
//
const DWORD MS_VC_EXCEPTION = 0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
	DWORD dwType; // Must be 0x1000.
	LPCSTR szName; // Pointer to name (in user addr space).
	DWORD dwThreadID; // Thread ID (MAXDWORD=caller thread).
	DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

void SetThreadName(std::string const &threadName)
{
	SetThreadName(threadName, MAXDWORD);
}

void SetThreadName(std::string const &threadName, DWORD dwThreadID)
{
	THREADNAME_INFO info;
	info.dwType = 0x1000;
	info.szName = threadName.c_str();
	info.dwThreadID = dwThreadID;
	info.dwFlags = 0;

	__try
	{
		RaiseException(MS_VC_EXCEPTION, 0, sizeof(info) / sizeof(ULONG_PTR), (ULONG_PTR*)&info);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
	}
}

void DebugEndMsg()
{
	if (debug)
		OutputDebugStringA("\n");
}

void DebugEndMsg(const CHAR* pszFormat, ...)
{
	if (debug)
	{
		va_list arglist;
		va_start(arglist, pszFormat);
		CHAR buf[1024];
		StringCchVPrintfA(buf, _countof(buf), pszFormat, arglist);
		va_end(arglist);
		OutputDebugStringA(buf);
		DebugEndMsg();
	}
}

void DebugContinueMsg(const CHAR* pszFormat, ...)
{
	if (debug)
	{
		CHAR buf[1024];
		va_list arglist;
		va_start(arglist, pszFormat);
		StringCchVPrintfA(buf, _countof(buf), pszFormat, arglist);
		va_end(arglist);
		OutputDebugStringA(buf);
	}
}
void DebugBeginMsg()
{
	if (debug)
	{
		CHAR buf[20];
		StringCchPrintfA(buf, _countof(buf), "(%lu): ", GetCurrentThreadId());
		OutputDebugStringA(buf);
	}
}

void DebugBeginMsg(const CHAR* pszFormat, ...)
{
	if (debug)
	{
		DebugBeginMsg();

		va_list arglist;
		va_start(arglist, pszFormat);
		CHAR buf[1024];
		StringCchVPrintfA(buf, _countof(buf), pszFormat, arglist);
		va_end(arglist);
		OutputDebugStringA(buf);
	}
}

void DebugMsg(const CHAR* pszFormat, ...)
{
	if (debug)
	{
		DebugBeginMsg();
		va_list arglist;
		va_start(arglist, pszFormat);
		CHAR buf[1024];
		StringCchVPrintfA(buf, _countof(buf), pszFormat, arglist);
		//DebugContinueMsg(pszFormat, arglist);
		va_end(arglist);
		OutputDebugStringA(buf);
		DebugEndMsg();
	}
}

void DebugMsg(const WCHAR* pszFormat, ...)
{
	if (debug)
	{
		WCHAR buf[1024];
		StringCchPrintfW(buf, sizeof(buf) / sizeof(WCHAR), L"(%lu): ", GetCurrentThreadId());
		va_list arglist;
		va_start(arglist, pszFormat);
		StringCchVPrintfW(&buf[wcslen(buf)], sizeof(buf) / sizeof(WCHAR), pszFormat, arglist);
		va_end(arglist);
		StringCchCatW(buf, sizeof(buf) / sizeof(WCHAR), L"\n");
		OutputDebugStringW(buf);
	}
}

void DebugHresult(const char* msg, HRESULT hr)
{
	if (debug)
	{
		char buf[1024];
		StringCchPrintfA(buf, _countof(buf), "(%lu): %s returned % #x (% S)\n", GetCurrentThreadId(), msg, hr, WinErrorMsg(hr).c_str());
		OutputDebugStringA(buf);
	}
}

void DebugHresult(const WCHAR* msg, HRESULT hr)
{
	if (debug)
	{
		WCHAR buf[1024];
		StringCchPrintfW(buf, _countof(buf), L"(%lu): %s returned % #x (% s)\n", GetCurrentThreadId(), msg, hr, WinErrorMsg(hr).c_str());
		OutputDebugStringW(buf);
	}
}

std::string HexDigits(const void* const buf, size_t len)
{
	CHAR rgbDigits[] = "0123456789abcdef";
	char formattedText[100];
	const auto* buffer = static_cast<const byte*>(buf);
	char formattedTextIndex = 0;

	size_t length = min(len, 16); // in c++17 this would be std::clamp((int)len, 0, 16);

	formattedText[formattedTextIndex++] = ' ';
	formattedText[formattedTextIndex++] = ':';
	formattedText[formattedTextIndex++] = ' ';

	for (size_t i = 0; i < length; i++) // step through each hexade
	{
		formattedText[formattedTextIndex++] = rgbDigits[buffer[i] >> 4];
		formattedText[formattedTextIndex++] = rgbDigits[buffer[i] & 0x0f];
		formattedText[formattedTextIndex++] = ' ';
		if (i == 7 && length > 8)
		{
			formattedText[formattedTextIndex++] = ':';
			formattedText[formattedTextIndex++] = ' ';
		}
	}
	if (false)
	{
		// Representation as ASCII characters
		formattedText[formattedTextIndex++] = ' ';
		formattedText[formattedTextIndex++] = '\"';
		for (size_t i = 0; i < length; i++)
		{
			formattedText[formattedTextIndex++] = (buffer[i] < 32 || buffer[i] > 126) ? '.' : buffer[i];
		}
		formattedText[formattedTextIndex++] = '\"';
	}	
	formattedText[formattedTextIndex++] = 0;
	std::string res(formattedText);
	return res;
}

static void PrintHexDumpActual(size_t length, const void * const buf, const bool verbose)
{
	size_t i, count, index;
	CHAR rgbDigits[] = "0123456789abcdef";
	CHAR rgbLine[100];
	const auto * buffer = static_cast<const byte *>(buf);

	if (!verbose && (length > 16))
		length = 16;

	for (index = 0; length; length -= count, buffer += count, index += count)
	{
		count = (length > 16) ? 16 : length;

		sprintf_s(rgbLine, sizeof(rgbLine), "%4Ix: ", index);
		char cbLine = 6;

		for (i = 0; i < count; i++)
		{
			rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
			rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
			if (i == 7)
			{
				rgbLine[cbLine++] = ':';
			}
			else
			{
				rgbLine[cbLine++] = ' ';
			}
		}
		for (; i < 16; i++)
		{
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
		}

		rgbLine[cbLine++] = ' ';

		for (i = 0; i < count; i++)
		{
			if (buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%')
				rgbLine[cbLine++] = '.';
			else
				rgbLine[cbLine++] = buffer[i];
		}
		rgbLine[cbLine++] = 0;
		DebugMsg(rgbLine);
	}
}

void PrintHexDump(const void *const buf, size_t length)
{
	if (debug) PrintHexDumpActual(length, buf, false);
}

void PrintHexDump(size_t length, const void * const buf)
{
	if (debug) PrintHexDumpActual(length, buf, false);
}

void PrintFullHexDump(size_t length, const void * const buf)
{
	if (debug) PrintHexDumpActual(length, buf, true);
}

bool IsUserAdmin()
{
	BOOL b;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup;
	b = AllocateAndInitializeSid(
		&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&AdministratorsGroup);
	if (b)
	{
		if (!CheckTokenMembership(nullptr, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return (b == TRUE);
}

#define STRINGIZE(n) Stringize(n)

// Utility function to get the version of the application
const char* const GetVersionText()
{
	return STRINGIZE(VERSION_MAJOR) "." STRINGIZE(VERSION_MINOR) "." STRINGIZE(VERSION_PATCH) "\0";
}