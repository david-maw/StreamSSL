#include "stdafx.h"
#include "Utilities.h"
#include <atlconv.h>

// General purpose functions

//
// Usage: SetThreadName ("MainThread"[, threadID]);
//
const DWORD MS_VC_EXCEPTION=0x406D1388;

#pragma pack(push,8)
typedef struct tagTHREADNAME_INFO
{
   DWORD dwType; // Must be 0x1000.
   LPCSTR szName; // Pointer to name (in user addr space).
   DWORD dwThreadID; // Thread ID (MAXDWORD=caller thread).
   DWORD dwFlags; // Reserved for future use, must be zero.
} THREADNAME_INFO;
#pragma pack(pop)

void SetThreadName(char* threadName)
{
	SetThreadName(threadName, MAXDWORD);
}

void SetThreadName(char* threadName, DWORD dwThreadID)
{
   THREADNAME_INFO info;
   info.dwType = 0x1000;
   info.szName = threadName;
   info.dwThreadID = dwThreadID;
   info.dwFlags = 0;

   __try
   {
      RaiseException( MS_VC_EXCEPTION, 0, sizeof(info)/sizeof(ULONG_PTR), (ULONG_PTR*)&info );
   }
   __except(EXCEPTION_EXECUTE_HANDLER)
   {
   }
}

void DebugMsg(const char* pszFormat, ...)
{
	if (debug)
	{
		char buf[1024];
		StringCchPrintfA(buf, sizeof(buf), "(%lu): ", GetCurrentThreadId());
		va_list arglist;
		va_start(arglist, pszFormat);
		StringCchVPrintfA(&buf[strlen(buf)], sizeof(buf), pszFormat, arglist);
		va_end(arglist);
		StringCchCatA(buf, sizeof(buf), "\n");
		OutputDebugStringA(buf);
	}
}

static void PrintHexDumpActual(DWORD length, const void * const buf, const bool verbose)
{
	DWORD i,count,index;
	CHAR rgbDigits[]="0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;
	const byte * buffer = static_cast<const byte *>(buf);

	if (verbose & (length>16))
		length = 16;

	for(index = 0; length; length -= count, buffer += count, index += count) 
	{
		count = (length > 16) ? 16:length;

		sprintf_s(rgbLine, sizeof(rgbLine), "%4.4x  ",index);
		cbLine = 6;

		for(i=0;i<count;i++) 
		{
			rgbLine[cbLine++] = rgbDigits[buffer[i] >> 4];
			rgbLine[cbLine++] = rgbDigits[buffer[i] & 0x0f];
			if(i == 7) 
			{
				rgbLine[cbLine++] = ':';
			} 
			else 
			{
				rgbLine[cbLine++] = ' ';
			}
		}
		for(; i < 16; i++) 
		{
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
			rgbLine[cbLine++] = ' ';
		}

		rgbLine[cbLine++] = ' ';

		for(i = 0; i < count; i++) 
		{
			if(buffer[i] < 32 || buffer[i] > 126 || buffer[i] == '%') 
				rgbLine[cbLine++] = '.';
			else 
				rgbLine[cbLine++] = buffer[i];
		}
		rgbLine[cbLine++] = 0;
		DebugMsg(rgbLine);
	}
}
void PrintHexDump(DWORD length, const void * const buf)
{
   if (debug) PrintHexDumpActual(length, buf, false);
}

void PrintHexDump(DWORD length, const void * const buf, const bool verbose)
{
	if (debug) PrintHexDumpActual(length, buf, verbose);
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
		if (!CheckTokenMembership(NULL, AdministratorsGroup, &b))
		{
			b = FALSE;
		}
		FreeSid(AdministratorsGroup);
	}

	return (b == TRUE);
}