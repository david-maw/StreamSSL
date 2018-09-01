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
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title);
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext);
bool MatchCertificateName(PCCERT_CONTEXT pCertContext, LPCWSTR hostname);
SECURITY_STATUS CertFindClientCertificate(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName = NULL, boolean fUserStore = true);
SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo);
CString GetHostName(COMPUTER_NAME_FORMAT WhichName = ComputerNameDnsHostname);
CString GetUserName(void);
CString GetCertName(PCCERT_CONTEXT pCertContext);

// defined in another source file (CreateCertificate.cpp)
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCWSTR Subject = NULL, LPCWSTR FriendlyName = NULL, LPCWSTR Description = NULL);