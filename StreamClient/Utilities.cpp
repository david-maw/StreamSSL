#include "stdafx.h"
#include "Utilities.h"
#include <strsafe.h>

void DebugMsg(const CHAR* pszFormat, ...)
{
    CHAR buf[1024];
    StringCchPrintfA(buf, sizeof(buf)/sizeof(CHAR), "(%lu): ", GetCurrentThreadId());
		va_list arglist;
		va_start(arglist, pszFormat);
		StringCchVPrintfA(&buf[strlen(buf)], sizeof(buf)/sizeof(CHAR), pszFormat, arglist);
		va_end(arglist);
    StringCchCatA(buf, sizeof(buf)/sizeof(CHAR), "\n");
	OutputDebugStringA(buf);
}

void DebugMsg(const WCHAR* pszFormat, ...)
{
    WCHAR buf[1024];
    StringCchPrintfW(buf, sizeof(buf)/sizeof(WCHAR), L"(%lu): ", GetCurrentThreadId());
		va_list arglist;
		va_start(arglist, pszFormat);
		StringCchVPrintfW(&buf[wcslen(buf)], sizeof(buf)/sizeof(WCHAR), pszFormat, arglist);
		va_end(arglist);
    StringCchCatW(buf, sizeof(buf)/sizeof(WCHAR), L"\n");
    OutputDebugStringW(buf);
}

static void PrintHexDumpActual(DWORD length, const void * const buf, const bool verbose)
{
	DWORD i,count,index;
	CHAR rgbDigits[]="0123456789abcdef";
	CHAR rgbLine[100];
	char cbLine;
	const byte * buffer = static_cast<const byte *>(buf);

	if (!verbose & (length>16))
		length = 16;

	for(index = 0; length; length -= count, buffer += count, index += count) 
	{
		count = (length > 16) ? 16:length;

		sprintf_s(rgbLine, sizeof(rgbLine), "%4.4x  ", index);
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
	if (debug)
	PrintHexDumpActual(length, buf, false);
}

void PrintHexDump(DWORD length, const void * const buf, const bool verbose)
{
	if (debug)
	PrintHexDumpActual(length, buf, verbose);
}