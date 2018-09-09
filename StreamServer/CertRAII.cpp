#include "stdafx.h"
#include <memory>
#include <vector>
#include "CertRAII.h"
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

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

CryptProvider::CryptProvider()
{
	// We always want a new keycontainer, so give it a unique name
	UUID uuid;
	RPC_STATUS ret_val = ::UuidCreate(&uuid);

	if (ret_val == RPC_S_OK)
	{
		// convert UUID to LPWSTR
		::UuidToString(&uuid, (RPC_WSTR*)&KeyContainerName);
		if (!KeyContainerName)
			DebugMsg("CryptProvider constructor could not initialize KeyContainerName");
	}
	else
		DebugMsg("CryptProvider constructor UuidCreate failed");
	// end of naming keycontainer
}

CryptProvider::~CryptProvider()
{
	if (hCryptProv)
	{
		DebugMsg(("CryptReleaseContext... "));
		CryptReleaseContext(hCryptProv, 0);
		DebugMsg("Success");
	}
	if (KeyContainerName)
	{
		// free up the allocated string
		::RpcStringFree((RPC_WSTR*)&KeyContainerName);
		KeyContainerName = NULL;
	}
}


BOOL CryptProvider::AcquireContext(DWORD dwFlags)
{
	return CryptAcquireContextW(&hCryptProv, KeyContainerName, NULL, PROV_RSA_FULL, dwFlags);
}

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

bool CertStore::CertOpenStore(DWORD dwFlags)
{
	hStore = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwFlags, L"My");
	return hStore != NULL;
}

bool CertStore::AddCertificateContext(PCCERT_CONTEXT pCertContext)
{
	return (FALSE != ::CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, 0));
}

// Cert class

Cert::Cert()
{
}

Cert::~Cert()
{
	if (pCertContext)
	{
		DebugMsg(("Destructor calling CertFreeCertificateContext... "));
		CertFreeCertificateContext(pCertContext);
		DebugMsg("Success");
	}
}

Cert::operator PCCERT_CONTEXT&()
{
	return pCertContext;
}

PCCERT_CONTEXT Cert::Detach()
{
	PCCERT_CONTEXT p = pCertContext;
	pCertContext = NULL;
	return p;
}

Cert::operator bool() const
{
	return pCertContext != NULL;
}

bool Cert::AddEnhancedKeyUsageIdentifier(LPCSTR pszUsageIdentifier)
{
	return FALSE != CertAddEnhancedKeyUsageIdentifier(pCertContext, pszUsageIdentifier);
}

bool Cert::SetCertificateContextProperty(DWORD dwPropId, DWORD dwFlags, const void *pvData)
{
	return FALSE != CertSetCertificateContextProperty(pCertContext, dwPropId, dwFlags, pvData);
}
