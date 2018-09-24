#pragma once
#include <security.h>
#include <functional>
#pragma comment(lib, "secur32.lib")
#include "SecurityHandle.h"

typedef std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)>  SelectServerCertType;
SECURITY_STATUS GetCredHandleFor(std::wstring serverName, SelectServerCertType SelectServerCert, PCredHandle phCreds);
