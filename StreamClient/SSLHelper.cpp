#include "stdafx.h"
#include "SSLHelper.h"
#include "SSLClient.h"

// Miscellaneous functions in support of SSL

// Create credentials (a handle to a certificate) by selecting an appropriate certificate
// We take a best guess at a certificate to be used as the SSL certificate for this client 
HRESULT CreateCredentials(LPCTSTR pszSubjectName, PCredHandle phCreds)
{
	HCERTSTORE  hMyCertStore = NULL;

	hMyCertStore = CertOpenSystemStore(NULL, _T("MY"));

	if (!hMyCertStore)
	{
		int err = GetLastError();

		if (err == ERROR_ACCESS_DENIED)
			DebugMsg("**** CertOpenStore failed with 'access denied'");
		else
			DebugMsg("**** Error %d returned by CertOpenStore", err);
		return HRESULT_FROM_WIN32(err);
	}

	PCCERT_CONTEXT  pCertContext = NULL;

   // Find a client certificate. Note that this code just searches for a 
	// certificate that contains the name somewhere in the subject name.
	// If we ever really start using user names there's probably a better scheme.
	//
	// If a subject name is not specified just create a NULL credential.
	//

	if (pszSubjectName)
	{
		pCertContext = CertFindCertificateInStore(hMyCertStore,
			X509_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR_A,
			pszSubjectName,
			NULL);
		if (!pCertContext)
		{
			DWORD Err = GetLastError();
         DebugMsg("**** Error 0x%x returned by CertFindCertificateInStore", Err);
			return HRESULT_FROM_WIN32(Err);
		}
	}

	// Build Schannel credential structure.
   SCHANNEL_CRED   SchannelCred = {0};
	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	if (pCertContext)
	{
		SchannelCred.cCreds = 1;
		SchannelCred.paCred = &pCertContext;
	}
	SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
	SchannelCred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

	SECURITY_STATUS Status;
	TimeStamp       tsExpiry;
	// Get a handle to the SSPI credential
	Status = CSSLClient::SSPI()->AcquireCredentialsHandle(
		NULL,                   // Name of principal
		UNISP_NAME,             // Name of package
		SECPKG_CRED_OUTBOUND,   // Flags indicating use
		NULL,                   // Pointer to logon ID
		&SchannelCred,          // Package specific data
		NULL,                   // Pointer to GetKey() func
		NULL,                   // Value to pass to GetKey()
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

	// Free the certificate context. Schannel has already made its own copy.
	if (pCertContext)
		CertFreeCertificateContext(pCertContext);

	return SEC_E_OK;
}

// Return an indication of whether a certificate is trusted by asking Windows to validate the
// trust chain (basically asking is the certificate issuer trusted)
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext)
{
	HTTPSPolicyCallbackData  polHttps;
	CERT_CHAIN_POLICY_PARA   PolicyPara;
	CERT_CHAIN_POLICY_STATUS PolicyStatus;
	CERT_CHAIN_PARA          ChainPara;
	PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
	HRESULT                  Status;
	LPSTR rgszUsages[] = { szOID_PKIX_KP_SERVER_AUTH,
		szOID_SERVER_GATED_CRYPTO,
		szOID_SGC_NETSCAPE };
	DWORD cUsages = _countof(rgszUsages);

	// Build certificate chain.
	ZeroMemory(&ChainPara, sizeof(ChainPara));
	ChainPara.cbSize = sizeof(ChainPara);
	ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	ChainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
	ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

	if (!CertGetCertificateChain(NULL,
		pCertContext,
		NULL,
		pCertContext->hCertStore,
		&ChainPara,
		0,
		NULL,
		&pChainContext))
	{
		Status = GetLastError();
		DebugMsg("Error %#x returned by CertGetCertificateChain!", Status);
		goto cleanup;
	}


	// Validate certificate chain.
	ZeroMemory(&polHttps, sizeof(HTTPSPolicyCallbackData));
	polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
	polHttps.dwAuthType = AUTHTYPE_SERVER;
	polHttps.fdwChecks = 0;    // dwCertFlags;
	polHttps.pwszServerName = NULL; // ServerName - checked elsewhere

	ZeroMemory(&PolicyPara, sizeof(PolicyPara));
	PolicyPara.cbSize = sizeof(PolicyPara);
	PolicyPara.pvExtraPolicyPara = &polHttps;

	ZeroMemory(&PolicyStatus, sizeof(PolicyStatus));
	PolicyStatus.cbSize = sizeof(PolicyStatus);

	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
		pChainContext,
		&PolicyPara,
		&PolicyStatus))
	{
		Status = HRESULT_FROM_WIN32(GetLastError());
		DebugMsg("Error %#x returned by CertVerifyCertificateChainPolicy!", Status);
		goto cleanup;
	}

	if (PolicyStatus.dwError)
	{
		Status = S_FALSE;
		//DisplayWinVerifyTrustError(PolicyStatus.dwError); 
		goto cleanup;
	}

	Status = SEC_E_OK;

cleanup:
	if (pChainContext)
		CertFreeCertificateChain(pChainContext);

	return Status;
}

// Does the name on the certificate match the name we provide
static HRESULT NamesMatch(LPCWSTR CertName, LPCWSTR ServerName)
{
	HRESULT hr = S_FALSE;
	// First, do a case insensitive compare, if the string are the same, we're done
	if (_wcsnicmp(CertName, ServerName, 256) == 0)
		return S_OK;
	// The strings were not the same, so see if the Servername was just the first node of the CertName
	CString Cert(CertName), Server(ServerName);
	// If the server name had a period in it, just give up
	if (Server.Find(L".") >= 0)
		return S_FALSE;
	// The cert name must be longer than the server name, or there's no hope 
	if (Server.GetLength() >= Cert.GetLength())
		return S_FALSE;
	// See if the cert name begins with the server name and a period, if so, call it a match
	Server += L".";
	Cert = Cert.Left(Server.GetLength());
	if (Cert.CompareNoCase(Server) == 0)
		return S_OK;
	return S_FALSE;
}

HRESULT CertNameMatches(PCCERT_CONTEXT pCertContext, LPCWSTR ServerName)
{
	WCHAR pszNameString[256];

	if (CertGetNameString(
		pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		pszNameString,
		128))
	{
		DebugMsg(L"Certificate name=%s", pszNameString);
		return NamesMatch(pszNameString, ServerName);
	}
	else
		DebugMsg("CertGetName failed.");

	return E_FAIL;
}

// Display a UI with the certificate info and also write it to the debug output
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title)
{
	TCHAR pszNameString[256];
	void*            pvData;
	DWORD            cbData;
	DWORD            dwPropId = 0;


	//  Display the certificate.
	if (!CryptUIDlgViewContext(
		CERT_STORE_CERTIFICATE_CONTEXT,
		pCertContext,
		NULL,
		CStringW(Title),
		0,
		NULL))
	{
		DebugMsg("UI failed.");
	}

	if (CertGetNameString(
		pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		NULL,
		pszNameString,
		128))
	{
		DebugMsg("Certificate for %S", ATL::CT2W(pszNameString));
	}
	else
		DebugMsg("CertGetName failed.");


	int Extensions = pCertContext->pCertInfo->cExtension;

	auto *p = pCertContext->pCertInfo->rgExtension;
	for (int i = 0; i < Extensions; i++)
	{
		DebugMsg("Extension %s", (p++)->pszObjId);
	}

	//-------------------------------------------------------------------
	// Loop to find all of the property identifiers for the specified  
	// certificate. The loop continues until 
	// CertEnumCertificateContextProperties returns zero.
	while (0 != (dwPropId = CertEnumCertificateContextProperties(
		pCertContext, // The context whose properties are to be listed.
		dwPropId)))    // Number of the last property found.  
		// This must be zero to find the first 
		// property identifier.
	{
		//-------------------------------------------------------------------
		// When the loop is executed, a property identifier has been found.
		// Print the property number.

		DebugMsg("Property # %d found->", dwPropId);

		//-------------------------------------------------------------------
		// Indicate the kind of property found.

		switch (dwPropId)
		{
		case CERT_FRIENDLY_NAME_PROP_ID:
		{
			DebugMsg("Friendly name: ");
			break;
		}
		case CERT_SIGNATURE_HASH_PROP_ID:
		{
			DebugMsg("Signature hash identifier ");
			break;
		}
		case CERT_KEY_PROV_HANDLE_PROP_ID:
		{
			DebugMsg("KEY PROVE HANDLE");
			break;
		}
		case CERT_KEY_PROV_INFO_PROP_ID:
		{
			DebugMsg("KEY PROV INFO PROP ID ");
			break;
		}
		case CERT_SHA1_HASH_PROP_ID:
		{
			DebugMsg("SHA1 HASH identifier");
			break;
		}
		case CERT_MD5_HASH_PROP_ID:
		{
			DebugMsg("md5 hash identifier ");
			break;
		}
		case CERT_KEY_CONTEXT_PROP_ID:
		{
			DebugMsg("KEY CONTEXT PROP identifier");
			break;
		}
		case CERT_KEY_SPEC_PROP_ID:
		{
			DebugMsg("KEY SPEC PROP identifier");
			break;
		}
		case CERT_ENHKEY_USAGE_PROP_ID:
		{
			DebugMsg("ENHKEY USAGE PROP identifier");
			break;
		}
		case CERT_NEXT_UPDATE_LOCATION_PROP_ID:
		{
			DebugMsg("NEXT UPDATE LOCATION PROP identifier");
			break;
		}
		case CERT_PVK_FILE_PROP_ID:
		{
			DebugMsg("PVK FILE PROP identifier ");
			break;
		}
		case CERT_DESCRIPTION_PROP_ID:
		{
			DebugMsg("DESCRIPTION PROP identifier ");
			break;
		}
		case CERT_ACCESS_STATE_PROP_ID:
		{
			DebugMsg("ACCESS STATE PROP identifier ");
			break;
		}
		case CERT_SMART_CARD_DATA_PROP_ID:
		{
			DebugMsg("SMART_CARD DATA PROP identifier ");
			break;
		}
		case CERT_EFS_PROP_ID:
		{
			DebugMsg("EFS PROP identifier ");
			break;
		}
		case CERT_FORTEZZA_DATA_PROP_ID:
		{
			DebugMsg("FORTEZZA DATA PROP identifier ");
			break;
		}
		case CERT_ARCHIVED_PROP_ID:
		{
			DebugMsg("ARCHIVED PROP identifier ");
			break;
		}
		case CERT_KEY_IDENTIFIER_PROP_ID:
		{
			DebugMsg("KEY IDENTIFIER PROP identifier ");
			break;
		}
		case CERT_AUTO_ENROLL_PROP_ID:
		{
			DebugMsg("AUTO ENROLL identifier. ");
			break;
		}
		case CERT_ISSUER_PUBLIC_KEY_MD5_HASH_PROP_ID:
		{
			DebugMsg("ISSUER PUBLIC KEY MD5 HASH identifier. ");
			break;
		}
		} // End switch.

		//-------------------------------------------------------------------
		// Retrieve information on the property by first getting the 
		// property size. 
		// For more information, see CertGetCertificateContextProperty.

		if (CertGetCertificateContextProperty(
			pCertContext,
			dwPropId,
			NULL,
			&cbData))
		{
			//  Continue.
		}
		else
		{
			// If the first call to the function failed,
			// exit to an error routine.
			DebugMsg("Call #1 to GetCertContextProperty failed.");
			return E_FAIL;
		}
		//-------------------------------------------------------------------
		// The call succeeded. Use the size to allocate memory 
		// for the property.

		if (NULL != (pvData = (void*)malloc(cbData)))
		{
			// Memory is allocated. Continue.
		}
		else
		{
			// If memory allocation failed, exit to an error routine.
			DebugMsg("Memory allocation failed.");
			return E_FAIL;
		}
		//----------------------------------------------------------------
		// Allocation succeeded. Retrieve the property data.

		if (CertGetCertificateContextProperty(
			pCertContext,
			dwPropId,
			pvData,
			&cbData))
		{
			// The data has been retrieved. Continue.
		}
		else
		{
			// If an error occurred in the second call, 
			// exit to an error routine.
			DebugMsg("Call #2 failed.");
			return E_FAIL;
		}
		//---------------------------------------------------------------
		// Show the results.

		DebugMsg("The Property Content is");
		PrintHexDump(cbData, pvData);

		//----------------------------------------------------------------
		// Free the certificate context property memory.

		free(pvData);
	}
	return S_OK;
}
