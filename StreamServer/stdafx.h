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

#define _AFXDLL
#include <afxwin.h>
#include <afxmt.h>

// Windows SDK
#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif
#include <WS2tcpip.h>
#define SECURITY_WIN32
#include <security.h>
#include <strsafe.h>

// Microsoft ToolKits
#include <tchar.h>

#ifndef VC_EXTRALEAN
#define VC_EXTRALEAN            // Exclude rarely-used stuff from Windows headers
#endif


// Standard C++
#include <functional>
#include <iostream>
#include <memory>

// Application
#include "ISocketStream.h"
#include "Listener.h"
#include "PassiveSock.h"
#include "SSLServer.h"
#include "Transport.h"
#include "Utilities.h"