#pragma once
#include "stdafx.h"
#include "wincrypt.h"
#pragma comment(lib, "crypt32.lib")

class CSP
{
public:
	CSP();
	~CSP();
	bool AcquirePrivateKey(PCCERT_CONTEXT pCertContext);
private:
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
};

class CryptProvider
{
public:
	WCHAR * KeyContainerName = NULL; // will create a random one in constructor
	CryptProvider();
	~CryptProvider();
	BOOL AcquireContext(DWORD dwFlags);

public:
	HCRYPTPROV hCryptProv = NULL;
};

class CryptKey
{
public:
	CryptKey();
	~CryptKey();
	BOOL CryptGenKey(CryptProvider& prov);

private:
	HCRYPTKEY hKey = NULL;
};

class CertStore
{
public:
	CertStore();
	~CertStore();
	HCERTSTORE get() const;
	operator bool() const;
	bool CertOpenStore(DWORD dwFlags);
	bool AddCertificateContext(PCCERT_CONTEXT pCertContext);

private:
	HCERTSTORE hStore = NULL;

};

class Cert
{
public:
	Cert();
	~Cert();
	operator PCCERT_CONTEXT&();
	operator bool() const;
	PCCERT_CONTEXT Detach();
	bool AddEnhancedKeyUsageIdentifier(LPCSTR pszUsageIdentifier);
	bool SetCertificateContextProperty(DWORD dwPropId, DWORD dwFlags, const void *pvData);


private:
	PCCERT_CONTEXT pCertContext = NULL;

};
