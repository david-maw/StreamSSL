#include "stdafx.h"
#include "wincrypt.h"
#pragma comment(lib, "crypt32.lib")
#include "Utilities.h"
// based on a sample found at:
// http://blogs.msdn.com/b/alejacma/archive/2009/03/16/how-to-create-a-self-signed-certificate-with-cryptoapi-c.aspx
// Create a self-signed certificate and store it in the machine personal store
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCWSTR Subject = NULL, LPCWSTR FriendlyName = NULL, LPCWSTR Description = NULL)
{
	// CREATE KEY PAIR FOR SELF-SIGNED CERTIFICATE

	HCRYPTPROV hCryptProv = NULL;
	HCRYPTKEY hKey = NULL;
	WCHAR * KeyContainerName = L"SSLTestKeyContainer";
   DWORD KeyFlags = MachineCert ? CRYPT_MACHINE_KEYSET : 0;
	try
	{
		// Acquire key container
		DebugMsg(("CryptAcquireContext of existing key container... "));
		if (!CryptAcquireContextW(&hCryptProv, KeyContainerName, NULL, PROV_RSA_FULL, KeyFlags))
		{
			int err = GetLastError();

			if (err == NTE_BAD_KEYSET)
				DebugMsg("**** CryptAcquireContext failed with 'bad keyset'");
			else
				DebugMsg("**** Error 0x%x returned by CryptAcquireContext", err);

			// Try to create a new key container
			DebugMsg(("CryptAcquireContext create new container... "));
			if (!CryptAcquireContextW(&hCryptProv, KeyContainerName, NULL, PROV_RSA_FULL, KeyFlags | CRYPT_NEWKEYSET))
			{
				int err = GetLastError();

				if (err == NTE_EXISTS)
					DebugMsg("**** CryptAcquireContext failed with 'already exists', are you running as administrator");
				else
					DebugMsg("**** Error 0x%x returned by CryptAcquireContext", err);
				// Error
				DebugMsg("Error 0x%x", GetLastError());
				return 0;
			}
			else
			{
				DebugMsg("Success - new container created");
			}
		}
		else
		{
			DebugMsg("Success - container found");
		}

		// Generate new key pair
		DebugMsg(("CryptGenKey... "));
		if (!CryptGenKey(hCryptProv, AT_SIGNATURE, 0x08000000 /*RSA-2048-BIT_KEY*/, &hKey))
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}
	}
   catch (...) {}

	// Clean up  

	if (hKey)
	{
		DebugMsg(("CryptDestroyKey... "));
		CryptDestroyKey(hKey);
		DebugMsg("Success");
	}
	if (hCryptProv)
	{
		DebugMsg(("CryptReleaseContext... "));
		CryptReleaseContext(hCryptProv, 0);
		DebugMsg("Success");
	}

	// CREATE SELF-SIGNED CERTIFICATE AND ADD IT TO PERSONAL STORE IN MACHINE PROFILE

	PCCERT_CONTEXT pCertContext = NULL;
	BYTE *pbEncoded = NULL;
	HCERTSTORE hStore = NULL;
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
	BOOL fCallerFreeProvOrNCryptKey = FALSE;

	try
	{
		// Encode certificate Subject
      CString X500(L"CN=");
      if (Subject)
         X500 += Subject;
      else
         X500 += L"localuser";
		DWORD cbEncoded = 0;
		// Find out how many bytes are needed to encode the certificate
		DebugMsg(("CertStrToName... "));
		if (!CertStrToName(X509_ASN_ENCODING, LPCWSTR(X500), CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}
		// Allocate the required space
		DebugMsg(("malloc... "));
		if (!(pbEncoded = (BYTE *)malloc(cbEncoded)))
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}
		// Encode the certificate
		DebugMsg(("CertStrToName... "));
		if (!CertStrToName(X509_ASN_ENCODING, LPCWSTR(X500), CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL))
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}

		// Prepare certificate Subject for self-signed certificate
		CERT_NAME_BLOB SubjectIssuerBlob;
		memset(&SubjectIssuerBlob, 0, sizeof(SubjectIssuerBlob));
		SubjectIssuerBlob.cbData = cbEncoded;
		SubjectIssuerBlob.pbData = pbEncoded;

		// Prepare key provider structure for certificate
		CRYPT_KEY_PROV_INFO KeyProvInfo;
		memset(&KeyProvInfo, 0, sizeof(KeyProvInfo));
		KeyProvInfo.pwszContainerName = KeyContainerName; // The key we made earlier
		KeyProvInfo.pwszProvName = NULL;
		KeyProvInfo.dwProvType = PROV_RSA_FULL;
		KeyProvInfo.dwFlags = KeyFlags;
		KeyProvInfo.cProvParam = 0;
		KeyProvInfo.rgProvParam = NULL;
		KeyProvInfo.dwKeySpec = AT_SIGNATURE;

		// Prepare algorithm structure for certificate
		CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
		memset(&SignatureAlgorithm, 0, sizeof(SignatureAlgorithm));
		SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

		// Prepare Expiration date for certificate
		SYSTEMTIME EndTime;
		GetSystemTime(&EndTime);
		EndTime.wYear += 5;

		// Create certificate
		DebugMsg(("CertCreateSelfSignCertificate... "));
		pCertContext = CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, 0);
		if (!pCertContext)
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}

      // Specify the allowed usage of the certificate (client or server authentication)
		DebugMsg(("CertAddEnhancedKeyUsageIdentifier"));
      LPCSTR szOID = MachineCert ? szOID_PKIX_KP_SERVER_AUTH : szOID_PKIX_KP_CLIENT_AUTH;
      if (CertAddEnhancedKeyUsageIdentifier(pCertContext, szOID))
		{
			DebugMsg("Success");
		}
		else
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}

      // Common variable used in several calls below
      CRYPT_DATA_BLOB cdblob;

      // Give the certificate a friendly name
      if (FriendlyName)
         cdblob.pbData = (BYTE*)FriendlyName;
      else
         cdblob.pbData = (BYTE*)L"SSLStream";
      cdblob.cbData = (wcslen((LPWSTR) cdblob.pbData) + 1) * sizeof(WCHAR);
		DebugMsg(("CertSetCertificateContextProperty CERT_FRIENDLY_NAME_PROP_ID"));
      if (CertSetCertificateContextProperty(pCertContext, CERT_FRIENDLY_NAME_PROP_ID, 0, &cdblob))
		{
			DebugMsg("Success");
		}
		else
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}

      // Give the certificate a description
      if (Description)
         cdblob.pbData = (BYTE*)Description;
      else if (MachineCert)
         cdblob.pbData = (BYTE*)L"SSLStream Server Test";
      else
         cdblob.pbData = (BYTE*)L"SSLStream Client Test";
      cdblob.cbData = (wcslen((LPWSTR) cdblob.pbData) + 1) * sizeof(WCHAR);
		DebugMsg(("CertSetCertificateContextProperty CERT_DESCRIPTION_PROP_ID"));
      if (CertSetCertificateContextProperty(pCertContext, CERT_DESCRIPTION_PROP_ID, 0, &cdblob))
		{
			DebugMsg("Success");
		}
		else
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}

		// Open Personal cert store in machine or user profile
		DebugMsg(("CertOpenStore to open root store... "));
		hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, 
         MachineCert ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER, L"My");
		if (!hStore)
		{
			// Error
			int err = GetLastError();

			if (err == ERROR_ACCESS_DENIED)
				DebugMsg("**** CertOpenStore failed with 'access denied' are  you running as administrator?");
			else
				DebugMsg("**** Error 0x%x returned by CertOpenStore", err);
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}

		// Add the cert to the store
		DebugMsg(("CertAddCertificateContextToStore... "));
		if (!CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0))
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success");
		}

		// Just for testing, verify that we can access cert's private key
		DWORD dwKeySpec;
		DebugMsg(("CryptAcquireCertificatePrivateKey... "));
		if (!CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
		{
			// Error
			DebugMsg("Error 0x%x", GetLastError());
			return 0;
		}
		else
		{
			DebugMsg("Success, private key acquired");
		}
	}
   catch (...){}

   // Clean up

	if (pbEncoded != NULL) {
		DebugMsg(("free... "));
		free(pbEncoded);
		DebugMsg("Success");
	}

	if (hCryptProvOrNCryptKey)
	{
		DebugMsg(("CryptReleaseContext... "));
		CryptReleaseContext(hCryptProvOrNCryptKey, 0);
		DebugMsg("Success");
	}

	if (hStore)
	{
		DebugMsg(("CertCloseStore... "));
		CertCloseStore(hStore, 0);
		DebugMsg("Success");
	}
	return pCertContext;
}