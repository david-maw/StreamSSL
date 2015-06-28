#pragma once
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include <schannel.h>
#include <cryptuiapi.h>
#pragma comment(lib,"cryptui.lib")
#include "Utilities.h"
#ifndef SCH_USE_STRONG_CRYPTO // Needs KB 2868725 which is only in Windows 7+
#define SCH_USE_STRONG_CRYPTO                        0x00400000
#endif
// handy functions declared in this file
HRESULT CreateCredentials(LPCTSTR pszSubjectName, PCredHandle phCreds); // forward declaration
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title); // forward declaration
HRESULT CertNameMatches(PCCERT_CONTEXT pCertContext, LPCTSTR ServerName);
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext);
