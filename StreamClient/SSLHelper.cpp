#include "stdafx.h"
#include "SSLHelper.h"
#include <algorithm>
#include <WinDNS.h>
#pragma comment(lib, "Dnsapi.lib")

// Miscellaneous functions in support of SSL

// Utility function to get the hostname of the host I am running on
CString GetHostName(COMPUTER_NAME_FORMAT WhichName)
{
   DWORD NameLength = 0;
   //BOOL R = GetComputerNameExW(ComputerNameDnsHostname, NULL, &NameLength);
   if (ERROR_SUCCESS == ::GetComputerNameEx(WhichName, NULL, &NameLength))
   {
      CString ComputerName;
      if (1 == ::GetComputerNameEx(WhichName, ComputerName.GetBufferSetLength(NameLength), &NameLength))
      {
         ComputerName.ReleaseBuffer();
         return ComputerName;
      }
   }
   return CString();
}

// Utility function to return the user name I'm runng under
CString GetUserName(void)
{
   DWORD NameLength = 0;
   //BOOL R = GetComputerNameExW(ComputerNameDnsHostname, NULL, &NameLength);
   if (ERROR_SUCCESS == ::GetUserName(NULL, &NameLength))
   {
      CString UserName;
      if (1 == ::GetUserName(UserName.GetBufferSetLength(NameLength), &NameLength))
      {
         UserName.ReleaseBuffer();
         return UserName;
      }
   }
   return CString();
}

// defined in another source file (CreateCertificate.cpp)
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCWSTR Subject = NULL, LPCWSTR FriendlyName = NULL, LPCWSTR Description = NULL);

bool HostNameMatches(CString HostName, PCWSTR pDNSName)
{
   CString DNSName(pDNSName);
   if (DnsNameCompare(HostName, pDNSName)) // The HostName is the DNSName
      return true;
   else if (DNSName.Find(L'*') < 0) // The DNSName is a hostname, but did not match
      return false;
   else // The DNSName is wildcarded
   {
      int suffixLen = HostName.GetLength() - HostName.Find(L'.'); // The length of the fixed part
      if (DNSName.GetLength() > suffixLen + 2) // the hostname domain part must be longer than the DNSName
         return false;
      else if (DNSName.GetLength() - DNSName.Find(L'.') != suffixLen) // The two suffix lengths must match
         return false;
      else if (HostName.Right(suffixLen) != DNSName.Right(suffixLen))
         return false;
      else // at this point, the decision is whether the last hostname node matches the wildcard
      {
         DNSName = DNSName.SpanExcluding(L".");
         CString HostShortName = HostName.SpanExcluding(L".");
         return (S_OK == PathMatchSpecEx(HostShortName, DNSName, PMSF_NORMAL));
      }
   }
}

// See http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.8+Adding+Hostname+Checking+to+Certificate+Verification/
// for a pre C++11 version of this algorithm
bool MatchCertHostName(PCCERT_CONTEXT pCertContext, LPCWSTR hostname) {
   /* Try SUBJECT_ALT_NAME2 first - it supercedes SUBJECT_ALT_NAME */
   auto szOID = szOID_SUBJECT_ALT_NAME2;
   auto pExtension = CertFindExtension(szOID, pCertContext->pCertInfo->cExtension,
      pCertContext->pCertInfo->rgExtension);
   if (!pExtension)
   {
      szOID = szOID_SUBJECT_ALT_NAME;
      pExtension = CertFindExtension(szOID, pCertContext->pCertInfo->cExtension,
         pCertContext->pCertInfo->rgExtension);
   }
   CString HostName(hostname);

   // Extract the SAN information (list of names) 
   DWORD cbStructInfo = -1;
   if (pExtension && CryptDecodeObject(X509_ASN_ENCODING, szOID,
      pExtension->Value.pbData, pExtension->Value.cbData, 0, 0, &cbStructInfo))
   {
      auto pvS = std::make_unique<byte[]>(cbStructInfo);
      CryptDecodeObject(X509_ASN_ENCODING, szOID, pExtension->Value.pbData,
         pExtension->Value.cbData, 0, pvS.get(), &cbStructInfo);
      auto pNameInfo = (CERT_ALT_NAME_INFO *)pvS.get();

      auto it = std::find_if(&pNameInfo->rgAltEntry[0], &pNameInfo->rgAltEntry[pNameInfo->cAltEntry], [HostName](_CERT_ALT_NAME_ENTRY Entry)
      {
         return Entry.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && HostNameMatches(HostName, Entry.pwszDNSName);
      }
      );
      return (it != &pNameInfo->rgAltEntry[pNameInfo->cAltEntry]); // left pointing past the end if not found
   }

   /* No SubjectAltName extension -- check CommonName */
   auto dwCommonNameLength = CertGetNameString(pCertContext, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, 0, 0);
   if (!dwCommonNameLength) // No CN found
      return false;
   CString CommonName;
   CertGetNameString(pCertContext, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, CommonName.GetBufferSetLength(dwCommonNameLength), dwCommonNameLength);
   CommonName.ReleaseBufferSetLength(dwCommonNameLength);
   return HostNameMatches(HostName, CommonName);
}

// Select, and return a handle to a client certificate
// We take a best guess at a certificate to be used as the SSL certificate for this client 
SECURITY_STATUS CertFindClient(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName)
{
   HCERTSTORE  hMyCertStore = NULL;
   TCHAR pszFriendlyNameString[128];
   TCHAR	pszNameString[128];

   if (pCertContext)
      return SEC_E_INVALID_PARAMETER;

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

   if (pCertContext)	// The caller passed in a certificate context we no longer need, so free it
      CertFreeCertificateContext(pCertContext);
   pCertContext = NULL;

   char * serverauth = szOID_PKIX_KP_CLIENT_AUTH;
   CERT_ENHKEY_USAGE eku;
   PCCERT_CONTEXT  pCertContextCurrent = NULL;
   eku.cUsageIdentifier = 1;
   eku.rgpszUsageIdentifier = &serverauth;
   // Find a client certificate. Note that this code just searches for a 
   // certificate that has the required enhanced key usage for server authentication
   // it then selects the best one (ideally one that contains the client name somewhere
   // in the subject name).

   while (NULL != (pCertContextCurrent = CertFindCertificateInStore(hMyCertStore,
      X509_ASN_ENCODING,
      CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG,
      CERT_FIND_ENHKEY_USAGE,
      &eku,
      pCertContextCurrent)))
   {
      //ShowCertInfo(pCertContext);
      if (!CertGetNameString(pCertContextCurrent, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszFriendlyNameString, sizeof(pszFriendlyNameString)))
      {
         DebugMsg("CertGetNameString failed getting friendly name.");
         continue;
      }
      DebugMsg("Certificate '%S' is allowed to be used for client authentication.", pszFriendlyNameString);
      if (!CertGetNameString(pCertContextCurrent, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, sizeof(pszNameString)))
      {
         DebugMsg("CertGetNameString failed getting subject name.");
         continue;
      }
      DebugMsg("   Subject name = %S.", pszNameString);
      // We must be able to access cert's private key
      HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
      BOOL fCallerFreeProvOrNCryptKey = FALSE;
      DWORD dwKeySpec;
      if (!CryptAcquireCertificatePrivateKey(pCertContextCurrent, 0, NULL, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
      {
         DWORD LastError = GetLastError();
         if (LastError == CRYPT_E_NO_KEY_PROPERTY)
            DebugMsg("   Certificate is unsuitable, it has no private key");
         else
            DebugMsg("   Certificate is unsuitable, its private key not accessible, Error = 0x%08x", LastError);
         continue; // Since it has no private key it is useless, just go on to the next one
      }
      // The minimum requirements are now met, 
      DebugMsg("   Certificate will be saved in case it is needed.");
      if (pCertContext)	// We have a saved certificate context we no longer need, so free it
         CertFreeCertificateContext(pCertContext);
      pCertContext = CertDuplicateCertificateContext(pCertContextCurrent);
      if (pszSubjectName && _tcscmp(pszNameString, pszSubjectName))
         DebugMsg("   Subject name does not match.");
      else
      {
         DebugMsg("   Certificate is ideal, terminating search.");
         break;
      }
   }

   if (!pCertContext)
   {
      DWORD LastError = GetLastError();
      DebugMsg("**** Error 0x%08x returned", LastError);
      return HRESULT_FROM_WIN32(LastError);
   }

   return SEC_E_OK;
}

SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo)
{
   PCCERT_CHAIN_CONTEXT pChainContext = NULL;
   CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara = { 0 };
   SECURITY_STATUS Status = SEC_E_CERT_UNKNOWN;
   HCERTSTORE  hMyCertStore = NULL;

   hMyCertStore = CertOpenSystemStore(NULL, _T("MY"));

   //
   // Enumerate possible client certificates.
   //

   FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
   FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
   FindByIssuerPara.dwKeySpec = 0;
   FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
   FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

   pChainContext = NULL;

   while (TRUE)
   {
      // Find a certificate chain.
      pChainContext = CertFindChainInStore(hMyCertStore,
         X509_ASN_ENCODING,
         0,
         CERT_CHAIN_FIND_BY_ISSUER,
         &FindByIssuerPara,
         pChainContext);
      if (pChainContext == NULL)
      {
         DWORD LastError = GetLastError();
         if (LastError == CRYPT_E_NOT_FOUND)
            DebugMsg("No certificate was found that chains to the one in the issuer list");
         else
            DebugMsg("Error 0x%08x finding cert chain", LastError);
         Status = HRESULT_FROM_WIN32(LastError);
         break;
      }
      DebugMsg("certificate chain found");
      // Get pointer to leaf certificate context.
      if (pCertContext)	// We have a saved certificate context we no longer need, so free it
         CertFreeCertificateContext(pCertContext);
      pCertContext = CertDuplicateCertificateContext(pChainContext->rgpChain[0]->rgpElement[0]->pCertContext);
      if (false && debug && pCertContext)
         ShowCertInfo(pCertContext, _T("Certificate at the end of the chain selected"));
      CertFreeCertificateChain(pChainContext);
      Status = SEC_E_OK;
      break;
   }
   return Status;
}

HRESULT FindCertificateByName(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName)
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

   pCertContext = NULL;

   // Find a client certificate. Note that this code just searches for a 
   // certificate that contains the name somewhere in the subject name.
   // If we ever really start using user names there's probably a better scheme.
   //
   // If a subject name is not specified just return a null credential.
   //

   if (pszSubjectName)
   {
      pCertContext = CertFindCertificateInStore(hMyCertStore,
         X509_ASN_ENCODING,
         0,
         CERT_FIND_SUBJECT_STR,
         pszSubjectName,
         NULL);
      if (pCertContext)
      {
         return S_OK;
      }
      else
      {
         DWORD Err = GetLastError();
         DebugMsg("**** Error 0x%x returned by CertFindCertificateInStore", Err);
         return HRESULT_FROM_WIN32(Err);
      }
   }
   else
      return S_FALSE; // Succeeded, but not S_OK
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
