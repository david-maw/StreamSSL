#pragma once
void PrintHexDump(DWORD length, const void * const buf, const bool verbose=true);
void DebugMsg(const WCHAR* pszFormat, ...);
void DebugMsg(const CHAR* pszFormat, ...);