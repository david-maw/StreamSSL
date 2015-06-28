#include "stdafx.h"
#include "SSLHelper.h"
#include "SSLServer.h"

// Miscellaneous functions in support of SSL

// defined in another source file (CreateCertificate.cpp)
PCCERT_CONTEXT CreateCertificate();

// Create credentials (a handle to a certificate) by selecting an appropriate certificate
// We take a best guess at a certificate to be used as the SSL certificate for this server 
HRESULT CreateCredentials(LPCTSTR pszSubjectName, PCredHandle phCreds, boolean fMachineStore)
{
	SCHANNEL_CRED   SchannelCred;
	TimeStamp       tsExpiry;
	SECURITY_STATUS Status;
	HCERTSTORE  hMyCertStore = NULL;
	TCHAR pszFriendlyNameString[128];
	TCHAR	pszNameString[128];

	if (pszSubjectName == NULL || _tcslen(pszSubjectName) == 0)
	{
		DebugMsg("**** No subject name specified!");
		return E_POINTER;
	}

	if (fMachineStore)
	{	// Open the local machine certificate store.
		hMyCertStore = CertOpenStore(CERT_STORE_PROV_SYSTEM,
			X509_ASN_ENCODING,
			NULL,
			CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG | CERT_SYSTEM_STORE_LOCAL_MACHINE,
			L"MY");
	}
	else // Open the store for this user
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

	char * serverauth = szOID_PKIX_KP_SERVER_AUTH;
	CERT_ENHKEY_USAGE eku;
	PCCERT_CONTEXT  pCertContext = NULL, pCertContextSaved = NULL;
	eku.cUsageIdentifier = 1;
	eku.rgpszUsageIdentifier = &serverauth;
	// Find a server certificate. Note that this code just searches for a 
	// certificate that has the required enhanced key usage for server authentication
   // it then selects the best one (ideall one that contains the server name somewhere
   // in the subject name.

	while (NULL != (pCertContext = CertFindCertificateInStore(hMyCertStore,
		X509_ASN_ENCODING,
		CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG,
		CERT_FIND_ENHKEY_USAGE,
		&eku,
		pCertContext)))
	{
		//ShowCertInfo(pCertContext);
		if (!CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, pszFriendlyNameString, sizeof(pszFriendlyNameString)))
		{
			DebugMsg("CertGetNameString failed getting friendly name.");
			continue;
		}
		DebugMsg("Certificate '%S' is allowed to be used for server authentication.", ATL::CT2W(pszFriendlyNameString));
		if (!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszNameString, sizeof(pszNameString)))
			DebugMsg("CertGetNameString failed getting subject name.");
		else if (_tcscmp(pszNameString, pszSubjectName))
			DebugMsg("Certificate has wrong subject name.");
		else if (CertCompareCertificateName(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, &pCertContext->pCertInfo->Issuer))
		{
			if (!pCertContextSaved)
			{
				DebugMsg("A self-signed certificate was found and saved in case it is needed.");
				pCertContextSaved = CertDuplicateCertificateContext(pCertContext);
			}
		}
		else
		{
			DebugMsg("Certificate is acceptable.");
			if (pCertContextSaved)	// We have a saved self signed certificate context we no longer need, so free it
				CertFreeCertificateContext(pCertContextSaved);
			pCertContextSaved = NULL;
			break;
		}
	}

	if (pCertContextSaved && !pCertContext)
	{	// We have a saved self-signed certificate and nothing better 
		DebugMsg("A self-signed certificate was the best we had.");
		pCertContext = pCertContextSaved;
		pCertContextSaved = NULL;
	}

	if (!pCertContext)
	{
		DWORD LastError = GetLastError();
		if (LastError == CRYPT_E_NOT_FOUND)
		{
			DebugMsg("**** CertFindCertificateInStore did not find a certificate, creating one");
			pCertContext = CreateCertificate();
			if (!pCertContext)
			{
				LastError = GetLastError();
				DebugMsg("**** Error 0x%x returned by CreateCertificate", LastError);
				std::cout << "Could not create certificate, are you running as administrator?" << std::endl;
				return HRESULT_FROM_WIN32(LastError);
			}
		}
		else
		{
			DebugMsg("**** Error 0x%x returned by CertFindCertificateInStore", LastError);
			return HRESULT_FROM_WIN32(LastError);
		}
	}

	if (!pCertContext)
	{
		DWORD LastError = GetLastError();
		if (LastError == CRYPT_E_NOT_FOUND)
		{
			DebugMsg("**** CertFindCertificateInStore did not find a certificate, creating one");
			pCertContext = CreateCertificate();
		}
		else
			DebugMsg("**** Error 0x%x returned by CertFindCertificateInStore", LastError);
		return HRESULT_FROM_WIN32(LastError);
	}

	// Build Schannel credential structure.
	ZeroMemory(&SchannelCred, sizeof(SchannelCred));
	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	SchannelCred.cCreds = 1;
	SchannelCred.paCred = &pCertContext;
	SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
	// Get a handle to the SSPI credential
	Status = CSSLServer::SSPI()->AcquireCredentialsHandle(
		NULL,                   // Name of principal
		UNISP_NAME,           // Name of package
		SECPKG_CRED_INBOUND,    // Flags indicating use
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

// General purpose helper class for SSL, decodes buffers for disgnosts, handles SNI

CSSLHelper::CSSLHelper(const byte * BufPtr, const int BufBytes):
contentType(0),
major(0),
minor(0),
length(0),
handshakeType(0),
handshakeLength(0),
OriginalBufPtr(BufPtr),
DataPtr(BufPtr),
MaxBufBytes(BufBytes)
{
   decoded = (BufPtr != nullptr) && CanDecode();
}

CSSLHelper::~CSSLHelper()
{
}

// Decode a buffer
bool CSSLHelper::CanDecode()
{
   if (MaxBufBytes < 5)
      return false;
   else
   {
      contentType = *(DataPtr++);
      major = *(DataPtr++);
      minor = *(DataPtr++);
      length = (*(DataPtr) << 8) + *(DataPtr + 1);
      DataPtr += 2;
      if (length + 5 > MaxBufBytes)
         return false;
      // This is a version we recognize
      if (contentType != 22)
         return false;
      // This is a handshake message (content type 22)
      handshakeType = *(DataPtr++);
      handshakeLength = (*DataPtr << 16) + (*(DataPtr + 1) << 8) + *(DataPtr + 2);
      DataPtr += 3;
      if (handshakeType != 1)
         return false;
      BufEnd = OriginalBufPtr + 5 + 4 + handshakeLength;
      return true;
   }
}

// Trace handshake buffer
void CSSLHelper::TraceHandshake()
{
   if (MaxBufBytes < 5)
      DebugMsg("Buffer space too small");
   else
   {
      const byte * BufPtr = DataPtr;
      if (length + 5 == MaxBufBytes)
         DebugMsg("Exactly one buffer is present");
      else if (length + 5 <= MaxBufBytes)
         DebugMsg("Whole buffer is present");
      else
         DebugMsg("Only part of the buffer is present");
      if (major == 3)
      {
         if (minor == 0)
            DebugMsg("SSL version 3.0");
         else if (minor == 1)
            DebugMsg("TLS version 1.0");
         else if (minor == 2)
            DebugMsg("TLS version 1.1");
         else if (minor == 3)
            DebugMsg("TLS version 1.2");
         else
            DebugMsg("TLS version after 1.2");
      }
      else
      {
         DebugMsg("Content Type = %d, Major.Minor Version = %d.%d, length %d (0x%04X)", contentType, major, minor, length, length);
         DebugMsg("This version is not recognized so no more information is available");
         PrintHexDump(MaxBufBytes, OriginalBufPtr);
         return;
      }
      // This is a version we recognize
      if (contentType != 22)
      {
         DebugMsg("This content type (%d) is not recognized", contentType);
         PrintHexDump(MaxBufBytes, OriginalBufPtr);
         return;
      }
      // This is a handshake message (content type 22)
      if (handshakeType != 1)
      {
         DebugMsg("This handshake type (%d) is not recognized", handshakeType);
         PrintHexDump(MaxBufBytes, OriginalBufPtr);
         return;
      }
      // This is a client hello message (handshake type 1)
      DebugMsg("client_hello");
      BufPtr += 2; // Skip ClientVersion
      BufPtr += 32; // Skip Random
      UINT8 sessionidLength = *BufPtr;
      BufPtr += 1 + sessionidLength; // Skip SessionID
      UINT16 cipherSuitesLength = (*(BufPtr) << 8) + *(BufPtr + 1);
      BufPtr += 2 + cipherSuitesLength; // Skip CipherSuites
      UINT8 compressionMethodsLength = *BufPtr;
      BufPtr += 1 + compressionMethodsLength; // Skip Compression methods
      bool extensionsPresent = BufPtr < BufEnd;
      UINT16 extensionsLength = (*(BufPtr) << 8) + *(BufPtr + 1);
      BufPtr += 2;
      if (extensionsLength == BufEnd - BufPtr)
         DebugMsg("There are %d bytes of extension data", extensionsLength);
      while (BufPtr < BufEnd)
      {
         UINT16 extensionType = (*(BufPtr) << 8) + *(BufPtr + 1);
         BufPtr += 2;
         UINT16 extensionDataLength = (*(BufPtr) << 8) + *(BufPtr + 1);
         BufPtr += 2;
         if (extensionType == 0) // server name list, in practice there's only ever one name in it (see RFC 6066)
         {
            UINT16 serverNameListLength = (*(BufPtr) << 8) + *(BufPtr + 1);
            BufPtr += 2;
            DebugMsg("Server name list extension, length %d", serverNameListLength);
            const byte * serverNameListEnd = BufPtr + serverNameListLength;
            while (BufPtr < serverNameListEnd)
            {
               UINT8 serverNameType = *(BufPtr++);
               UINT16 serverNameLength = (*(BufPtr) << 8) + *(BufPtr + 1);
               BufPtr += 2;
               if (serverNameType == 0)
                  DebugMsg("   Requested name \"%*s\"", serverNameLength, BufPtr);
               else
                  DebugMsg("   Server name Type %d, length %d, data \"%*s\"", serverNameType, serverNameLength, serverNameLength, BufPtr);
               BufPtr += serverNameLength;
            }
         }
         else
         {
            DebugMsg("Extension Type %d, length %d", extensionType, extensionDataLength);
            BufPtr += extensionDataLength;
         }
      }
      if (BufPtr == BufEnd)
         DebugMsg("Extensions exactly filled the header, as expected");
      else
         DebugMsg("** Error ** Extensions did not fill the header");
   }
   PrintHexDump(MaxBufBytes, OriginalBufPtr);
   return;
}

// Is this packet a complete client initialize packet
bool CSSLHelper::IsClientInitialize()
{
   return decoded;
}

// Get SNI provided hostname
CString CSSLHelper::GetSNI()
{
   const byte * BufPtr = DataPtr;
   if (decoded)
   {
      // This is a client hello message (handshake type 1)
      BufPtr += 2; // Skip ClientVersion
      BufPtr += 32; // Skip Random
      UINT8 sessionidLength = *BufPtr;
      BufPtr += 1 + sessionidLength; // Skip SessionID
      UINT16 cipherSuitesLength = (*(BufPtr) << 8) + *(BufPtr + 1);
      BufPtr += 2 + cipherSuitesLength; // Skip CipherSuites
      UINT8 compressionMethodsLength = *BufPtr;
      BufPtr += 1 + compressionMethodsLength; // Skip Compression methods
      bool extensionsPresent = BufPtr < BufEnd;
      UINT16 extensionsLength = (*(BufPtr) << 8) + *(BufPtr + 1);
      BufPtr += 2;
      while (BufPtr < BufEnd)
      {
         UINT16 extensionType = (*(BufPtr) << 8) + *(BufPtr + 1);
         BufPtr += 2;
         UINT16 extensionDataLength = (*(BufPtr) << 8) + *(BufPtr + 1);
         BufPtr += 2;
         if (extensionType == 0) // server name list, in practice there's only ever one name in it (see RFC 6066)
         {
            UINT16 serverNameListLength = (*(BufPtr) << 8) + *(BufPtr + 1);
            BufPtr += 2;
            const byte * serverNameListEnd = BufPtr + serverNameListLength;
            while (BufPtr < serverNameListEnd)
            {
               UINT8 serverNameType = *(BufPtr++);
               UINT16 serverNameLength = (*(BufPtr) << 8) + *(BufPtr + 1);
               BufPtr += 2;
               if (serverNameType == 0)
                  return CString((char*)BufPtr, serverNameLength);
               BufPtr += serverNameLength;
            }
         }
         else
         {
            BufPtr += extensionDataLength;
         }
      }
   }
   return CString();
}
