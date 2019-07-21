#pragma once
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")

/*
This is one of 2 different approaches to handling old Windows handle classes.

The approach in "SecurityHandle.h" encapsulates the native handles but leaves the class usage
somewhat untouched (certainly not quite untouched, since handle usages tend to be replaced by
"get" or "set" calls, but generally the notion of a handle to an object is preserved with lifetime
management using RAII added.

The approach in "CertRAII...." also replaces handles with objects encapsulating the handles, but
these behave as if they were the underlying object. So, for example instead of a "CertContextHandle"
class, we have a "CertStore" class with a CertStore::AddCertificateContext method, which ultimately
calls ::CertAddCertificateContextToStore. This works fine if only a relatively small number
of methods are to be called, but since each one has to be added to the class, it can be a pain
if a lot of methods are needed so the SecurityHandle.h approach works better then.
*/

class CSP
{
public:
	CSP() = default;
	~CSP();
	bool AcquirePrivateKey(PCCERT_CONTEXT pCertContext);
private:
	HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
};

class CryptProvider
{
public:
	WCHAR * KeyContainerName = nullptr; // will create a random one in constructor
	CryptProvider();
	~CryptProvider();
	BOOL AcquireContext(DWORD dwFlags);

public:
	HCRYPTPROV hCryptProv = NULL;
};

class CryptKey
{
public:
	CryptKey() = default;
	~CryptKey();
	BOOL CryptGenKey(CryptProvider& prov);

private:
	HCRYPTKEY hKey = NULL;
};

class CertStore
{
public:
	CertStore() = default;
	~CertStore();
	HCERTSTORE get() const;
	operator bool() const;
	bool CertOpenStore(DWORD dwFlags);
	bool AddCertificateContext(PCCERT_CONTEXT pCertContext);

private:
	HCERTSTORE hStore = nullptr;

};
