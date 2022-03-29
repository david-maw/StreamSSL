#pragma once

#include "targetver.h"
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

// The following commented code is for debugging memory leaks
//#define _CRTDBG_MAP_ALLOC  
//#include <stdlib.h>  
//#include <crtdbg.h>
//#ifdef _DEBUG
//#define DBG_NEW new ( _NORMAL_BLOCK , __FILE__ , __LINE__ )
//// Replace _NORMAL_BLOCK with _CLIENT_BLOCK if you want the
//// allocations to be of _CLIENT_BLOCK type
//#else
//#define DBG_NEW new
//#endif

// Define a bool to check if this is a DEBUG or RELEASE build
#ifndef DEBUGFLAG_DEFINED
#define DEBUGFLAG_DEFINED
#if defined(_DEBUG)
const bool debug = true;
#else
const bool debug = false;
#endif
#endif // DEBUGFLAG_DEFINED

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif

#include <winsock2.h>
#include <windows.h>
#include <tchar.h>

#include <WS2tcpip.h>
#define SECURITY_WIN32
#include <security.h>
#include <strsafe.h>

// Standard C++
#include <iostream>
