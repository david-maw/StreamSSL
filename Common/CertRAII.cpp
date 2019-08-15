#include "pch.h"
#include "framework.h"

#include "CertRAII.h"
#include "Utilities.h"

#include <memory>
#include <vector>
#include <Rpc.h>
#pragma comment(lib, "Rpcrt4.lib")

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
	return FALSE != CryptAcquireCertificatePrivateKey(pCertContext, 0, nullptr, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey);
}

CryptProvider::CryptProvider()
{
	// We always want a new keycontainer, so give it a unique name
	UUID uuid;
	RPC_STATUS ret_val = ::UuidCreate(&uuid);

	if (ret_val == RPC_S_OK)
	{
		// convert UUID to LPWSTR
		ret_val = ::UuidToString(&uuid, (RPC_WSTR*)&KeyContainerName);
		if (FAILED(ret_val) || !KeyContainerName)
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
		KeyContainerName = nullptr;
	}
}


BOOL CryptProvider::AcquireContext(DWORD dwFlags)
{
	return CryptAcquireContextW(&hCryptProv, KeyContainerName, nullptr, PROV_RSA_FULL, dwFlags);
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


CertStore::~CertStore()
{
	if (hStore)
	{
		DebugMsg("CertStore destructor calling CertCloseStore(0x%.8x)", hStore);
		CertCloseStore(hStore, 0);
	}
}

bool CertStore::CertOpenStore(DWORD dwFlags)
{
	hStore = ::CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, 0, dwFlags, L"My");
	return hStore != nullptr;
}

bool CertStore::AddCertificateContext(PCCERT_CONTEXT pCertContext)
{
	return (FALSE != ::CertAddCertificateContextToStore(hStore, pCertContext, CERT_STORE_ADD_REPLACE_EXISTING, nullptr));
}

CertStore::operator bool() const
{
	return hStore != nullptr;
}

HCERTSTORE CertStore::get() const
{
	return hStore;
}
