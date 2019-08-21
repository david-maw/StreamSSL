#pragma once
#include "SecurityHandle.h"

#include <security.h>
#include <functional>
#pragma comment(lib, "secur32.lib")

using SelectServerCertType = std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)>;
SECURITY_STATUS GetCredHandleFor(std::wstring serverName, SelectServerCertType SelectServerCert, PCredHandle phCreds);
