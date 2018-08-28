#include "stdafx.h"
#include "wincrypt.h"
#pragma comment(lib, "crypt32.lib")
#include <memory>
#include <vector>
// based on a sample found at:
// http://blogs.msdn.com/b/alejacma/archive/2009/03/16/how-to-create-a-self-signed-certificate-with-cryptoapi-c.aspx
// Create a self-signed certificate and store it in the machine personal store

class CSP
{
public:
	CSP();
	~CSP();
	bool AcquirePrivateKey(PCCERT_CONTEXT pCertContext);
private:
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
};

CSP::CSP()
{
}

CSP::~CSP()
{
	if (hCryptProvOrNCryptKey)
	{
		DebugMsg(("CryptReleaseContext... "));
		CryptReleaseContext(hCryptProvOrNCryptKey, 0);
		DebugMsg("Success");
	}
}

bool CSP::AcquirePrivateKey(PCCERT_CONTEXT pCertContext)
{
	BOOL fCallerFreeProvOrNCryptKey = FALSE;
	DWORD dwKeySpec;
	return FALSE != CryptAcquireCertificatePrivateKey(pCertContext, 0, NULL, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey);
}


class CryptProvider
{
public:
	WCHAR * KeyContainerName = L"SSLTestKeyContainer";
	CryptProvider();
	~CryptProvider();
	BOOL AcquireContext(DWORD dwFlags);

public:
	HCRYPTPROV hCryptProv = NULL;
};

CryptProvider::CryptProvider()
{
}

CryptProvider::~CryptProvider()
{
	if (hCryptProv)
	{
		DebugMsg(("CryptReleaseContext... "));
		CryptReleaseContext(hCryptProv, 0);
		DebugMsg("Success");
	}
}


BOOL CryptProvider::AcquireContext(DWORD dwFlags)
{
	return CryptAcquireContextW(&hCryptProv, KeyContainerName, NULL, PROV_RSA_FULL, dwFlags);
}



class CryptKey
{
public:
	CryptKey();
	~CryptKey();
	BOOL CryptGenKey(CryptProvider& prov);

private:
	HCRYPTKEY hKey = NULL;
};

CryptKey::CryptKey()
{
}

CryptKey::~CryptKey()
{
	if (hKey)
	{
		DebugMsg(("Destructor calling CryptDestroyKey... "));
		CryptDestroyKey(hKey);
		DebugMsg("Success");
	}
}

BOOL CryptKey::CryptGenKey(CryptProvider& prov)
{
	return ::CryptGenKey(prov.hCryptProv, AT_SIGNATURE, 0x08000000 /*RSA-2048-BIT_KEY*/, &hKey);
}

class CertStore
{
public:
	CertStore();
	~CertStore();
	bool CertOpenStore();
	bool AddCertificateContext(PCCERT_CONTEXT pCertContext);

private:
	HCERTSTORE hStore = NULL;

};

CertStore::CertStore()
{
}

CertStore::~CertStore()
{
	if (hStore)
	{
		DebugMsg(("CertCloseStore... "));
		CertCloseStore(hStore, 0);
		DebugMsg("Success");
	}
}

bool CertStore::CertOpenStore()
{
	hStore = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, CERT_SYSTEM_STORE_LOCAL_MACHINE, L"My");
	return hStore != NULL;
}

bool CertStore::AddCertificateContext(PCCERT_CONTEXT pCertContext)
{
	return (FALSE != ::CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0));
}


PCCERT_CONTEXT CreateCertificate()
{
	// CREATE KEY PAIR FOR SELF-SIGNED CERTIFICATE IN MACHINE PROFILE
	CryptProvider cryptprovider;
	CryptKey key;
	// Acquire key container
	DebugMsg(("CryptAcquireContext of existing key container... "));
	if (!cryptprovider.AcquireContext(CRYPT_MACHINE_KEYSET))
	{
		int err = GetLastError();

		if (err == NTE_BAD_KEYSET)
			DebugMsg("**** CryptAcquireContext failed with 'bad keyset'");
		else
			DebugMsg("**** Error 0x%x returned by CryptAcquireContext", err);

		// Try to create a new key container
		DebugMsg(("CryptAcquireContext create new container... "));
		if (!cryptprovider.AcquireContext(CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
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
	if (!key.CryptGenKey(cryptprovider))
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}
	else
	{
		DebugMsg("Success");
	}

	// CREATE SELF-SIGNED CERTIFICATE AND ADD IT TO PERSONAL STORE IN MACHINE PROFILE

	PCCERT_CONTEXT pCertContext = NULL;
	std::vector<BYTE> CertName;

	// Encode certificate Subject
	LPCWSTR pszX500 = L"CN=localhostXX";
	DWORD cbEncoded = 0;
	// Find out how many bytes are needed to encode the certificate
	DebugMsg(("CertStrToName... "));
	if (CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, NULL, &cbEncoded, NULL))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}
	// Allocate the required space
	CertName.resize(cbEncoded);
	// Encode the certificate
	DebugMsg(("CertStrToName... "));
	if (CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, &CertName[0], &cbEncoded, NULL))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}

	// Prepare certificate Subject for self-signed certificate
	CERT_NAME_BLOB SubjectIssuerBlob{ 0 };
	SubjectIssuerBlob.cbData = cbEncoded;
	SubjectIssuerBlob.pbData = &CertName[0];

	// Prepare key provider structure for certificate
	CRYPT_KEY_PROV_INFO KeyProvInfo{ 0 };
	KeyProvInfo.pwszContainerName = cryptprovider.KeyContainerName;
	KeyProvInfo.pwszProvName = NULL;
	KeyProvInfo.dwProvType = PROV_RSA_FULL;
	KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
	KeyProvInfo.cProvParam = 0;
	KeyProvInfo.rgProvParam = NULL;
	KeyProvInfo.dwKeySpec = AT_SIGNATURE;

	// Prepare algorithm structure for certificate
	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm{ 0 };
	SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;

	// Prepare Expiration date for certificate
	SYSTEMTIME EndTime;
	GetSystemTime(&EndTime);
	EndTime.wYear += 5;

	// Create certificate
	DebugMsg(("CertCreateSelfSignCertificate... "));
	pCertContext = CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, 0);
	if (pCertContext)
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}

	// Specify the allowed usage of the certificate (server authentication)
	DebugMsg(("CertAddEnhancedKeyUsageIdentifier"));
	if (CertAddEnhancedKeyUsageIdentifier(pCertContext, szOID_PKIX_KP_SERVER_AUTH))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}

	// Common variable used in several calls below
	CRYPT_DATA_BLOB cdblob;

	// Give the certificate a friendly name
	cdblob.pbData = (BYTE*)L"SSLStream Testing";
	cdblob.cbData = (wcslen((LPWSTR)cdblob.pbData) + 1) * sizeof(WCHAR);
	DebugMsg(("CertSetCertificateContextProperty CERT_FRIENDLY_NAME_PROP_ID"));
	if (CertSetCertificateContextProperty(pCertContext, CERT_FRIENDLY_NAME_PROP_ID, 0, &cdblob))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}

	// Give the certificate a description
	cdblob.pbData = (BYTE*)L"SSL Stream Server Test";
	cdblob.cbData = (wcslen((LPWSTR)cdblob.pbData) + 1) * sizeof(WCHAR);
	DebugMsg(("CertSetCertificateContextProperty CERT_DESCRIPTION_PROP_ID"));
	if (CertSetCertificateContextProperty(pCertContext, CERT_DESCRIPTION_PROP_ID, 0, &cdblob))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}

	// Open Personal cert store in machine profile
	DebugMsg(("CertOpenStore to open root store... "));
	CertStore store;
	if (store.CertOpenStore())
		DebugMsg("Success");
	else
	{
		// Error
		int err = GetLastError();

		if (err == ERROR_ACCESS_DENIED)
			DebugMsg("**** CertOpenStore failed with 'access denied' are  you running as administrator?");
		else
			DebugMsg("**** Error 0x%x returned by CertOpenStore", err);
		return 0;
	}

	// Add the cert to the store
	DebugMsg(("CertAddCertificateContextToStore... "));
	if (!store.AddCertificateContext(pCertContext))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}

	// Just for testing, verify that we can access cert's private key
	DebugMsg(("CryptAcquireCertificatePrivateKey... "));
	CSP csp;
	if (csp.AcquirePrivateKey(pCertContext))
		DebugMsg("Success, private key acquired");
	else
	{
		// Error
		DebugMsg("Error 0x%x", GetLastError());
		return 0;
	}
	return pCertContext;
}