#include "pch.h"
#include "framework.h"

#include "ServerCert.h"
#include "CertHelper.h"
#include "SSLServer.h"
#include "Utilities.h"

#include <unordered_map>
#include <mutex>

// Create credentials (a handle to a credential context) from a certificate
SECURITY_STATUS CreateCredentialsFromCertificate(PCredHandle phCreds, PCCERT_CONTEXT pCertContext)
{
	DebugMsg("CreateCredentialsFromCertificate 0x%.8x '%S'.", pCertContext, GetCertName(pCertContext).c_str());

	// Build Schannel credential structure.
	SCHANNEL_CRED   SchannelCred = { 0 };
	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	SchannelCred.cCreds = 1;
	SchannelCred.paCred = &pCertContext;
	SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
	SchannelCred.dwFlags = SCH_USE_STRONG_CRYPTO;

	SECURITY_STATUS Status;
	TimeStamp       tsExpiry;
	// Get a handle to the SSPI credential
	Status = CSSLServer::SSPI()->AcquireCredentialsHandle(
		nullptr,                   // Name of principal
		const_cast<WCHAR*>(UNISP_NAME), // Name of package
		SECPKG_CRED_INBOUND,    // Flags indicating use
		nullptr,                   // Pointer to logon ID
		&SchannelCred,          // Package specific data
		nullptr,                   // Pointer to GetKey() func
		nullptr,                   // Value to pass to GetKey()
		phCreds,                // (out) Cred Handle
		&tsExpiry);             // (out) Lifetime (optional)

	if (Status != SEC_E_OK)
	{
		DWORD dw = GetLastError();
		if (Status == SEC_E_UNKNOWN_CREDENTIALS)
			DebugMsg("**** Error: 'Unknown Credentials' returned by AcquireCredentialsHandle. Be sure app has administrator rights. LastError=%d", dw);
		else
			DebugMsg("**** Error 0x%x returned by AcquireCredentialsHandle. LastError=%d.", Status, dw);
		return Status;
	}

	return SEC_E_OK;
}

// Global items used by the GetCredHandleFor function
std::mutex GetCredHandleForLock;
std::unordered_map<std::wstring, CredentialHandle> credMap = std::unordered_map<std::wstring, CredentialHandle>();

SECURITY_STATUS GetCredHandleFor(std::wstring serverName, SelectServerCertType SelectServerCert, PCredHandle phCreds)
{
	std::wstring localServerName;
	if (serverName.empty()) // There was no hostname supplied
		localServerName = GetHostName();
	else
		localServerName = serverName;

	std::lock_guard<std::mutex> lock(GetCredHandleForLock); // unordered_map is not thread safe, so make this function single thread

	auto got = credMap.find(localServerName);

	if (got == credMap.end())
	{
		// There were no credentials stored for that host, create some and add them
		PCCERT_CONTEXT pCertContext = nullptr;
		SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
		if (SelectServerCert)
		{
			status = SelectServerCert(pCertContext, serverName.c_str());
			if (FAILED(status))
			{
				DebugMsg("SelectServerCert returned an error = 0x%08x", status);
				return SEC_E_INTERNAL_ERROR;
			}
		}
		else
			status = CertFindServerCertificateByName(pCertContext, serverName.c_str()); // Add "true" to look in user store, "false", or nothing looks in machine store
		if (SUCCEEDED(status))
		{
			CredHandle hServerCred{};
			status = CreateCredentialsFromCertificate(&hServerCred, pCertContext);
			if SUCCEEDED(status)
			{
				credMap.emplace(localServerName, hServerCred); // The server credentials are owned by the map now
				*phCreds = hServerCred;
			}
			return status;
		}
		else
		{
			DebugMsg("Failed handling server initialization, error = 0x%08x", status);
			return SEC_E_INTERNAL_ERROR;
		}
	}
	else // We already have credentials for this one
	{
		*phCreds = (got->second).get();
		return SEC_E_OK;
	}
}
