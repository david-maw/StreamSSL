#include "pch.h"
#include "framework.h"

#include "CertHelper.h"
#include "CertRAII.h"
#include "SecurityHandle.h"
#include "Utilities.h"

#include <algorithm>
#include <vector>
#include <cryptuiapi.h>
#include <string>
#include <WinDNS.h>

#pragma comment(lib, "Cryptui.lib")
#pragma comment(lib, "Dnsapi.lib")

static CertStore userStore{}, machineStore{}; // These stores are intended to stay open and be reused once used

// Open the required user of machine store and cache it so you can hand back handles to it
// The returned handles should NOT be closed after use
SECURITY_STATUS GetStore(HCERTSTORE &phStore, bool useUserStore)
{
	CertStore * certStore = useUserStore ? &userStore : &machineStore;
	if (!*certStore)
		{
			if (!certStore->CertOpenStore(CERT_STORE_OPEN_EXISTING_FLAG | CERT_STORE_READONLY_FLAG |
				(useUserStore ? CERT_SYSTEM_STORE_CURRENT_USER : CERT_SYSTEM_STORE_LOCAL_MACHINE)))
			{
				int err = GetLastError();

				if (err == ERROR_ACCESS_DENIED)
					DebugMsg("**** GetStore failed with 'access denied'");
				else
					DebugMsg("**** Error %d returned by CertOpenStore", err);
				return HRESULT_FROM_WIN32(err);
			}
		}
	phStore = certStore->get();
	return SEC_E_OK;
}

// Match the required name (HostName) to the name on the certificate pRequiredName, which might be wildcarded
bool DnsNameMatches(std::wstring HostName, PCWSTR pRequiredName)
{
	if (DnsNameCompare(HostName.c_str(), pRequiredName)) // The HostName is the RequiredName
		return true;
	else if (*pRequiredName != L'*') // The RequiredName is not a wildcarded hostname
		return false;
	else // The RequiredName is wildcarded, something like *.unisys.com (wildcards represent whole nodes)
	{
		std::wstring RequiredName(pRequiredName);
		const auto suffixLen = HostName.length() - HostName.find(L'.'); // The length of the domain part
		if ((RequiredName.length() != suffixLen + 1) && (RequiredName[0] != L'*')) // our wildcard names must begin with "*..."
			return false;
		else if (RequiredName.length() - RequiredName.find(L'.') != suffixLen) // The two suffix lengths must match
			return false;
		else
			return (HostName.length() - HostName.find(L'.') == suffixLen); // if only the first node differs, we're good to go
	}
}

// See http://etutorials.org/Programming/secure+programming/Chapter+10.+Public+Key+Infrastructure/10.8+Adding+Hostname+Checking+to+Certificate+Verification/
// for a pre C++11 version of this algorithm
bool MatchCertificateName(PCCERT_CONTEXT pCertContext, LPCWSTR pszRequiredName) {
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
	std::wstring RequiredName(pszRequiredName);

	// Extract the SAN information (list of names) 
	DWORD cbStructInfo = 0;
	if (pExtension && CryptDecodeObject(X509_ASN_ENCODING, szOID,
		pExtension->Value.pbData, pExtension->Value.cbData, 0, nullptr, &cbStructInfo))
	{
		auto pvS = std::make_unique<byte[]>(cbStructInfo);
		CryptDecodeObject(X509_ASN_ENCODING, szOID, pExtension->Value.pbData,
			pExtension->Value.cbData, 0, pvS.get(), &cbStructInfo);
		auto pNameInfo = (CERT_ALT_NAME_INFO *)pvS.get();

		auto it = std::find_if(&pNameInfo->rgAltEntry[0], &pNameInfo->rgAltEntry[pNameInfo->cAltEntry], [RequiredName](_CERT_ALT_NAME_ENTRY Entry)
		{
			return Entry.dwAltNameChoice == CERT_ALT_NAME_DNS_NAME && DnsNameMatches(RequiredName, Entry.pwszDNSName);
		}
		);
		return (it != &pNameInfo->rgAltEntry[pNameInfo->cAltEntry]); // left pointing past the end if not found
	}

	/* No SubjectAltName extension -- check CommonName */
	auto dwCommonNameLength = CertGetNameString(pCertContext, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(szOID_COMMON_NAME), 0, 0);
	if (!dwCommonNameLength) // No CN found
		return false;
	std::wstring CommonName;
	CommonName.resize(dwCommonNameLength);
	CertGetNameString(pCertContext, CERT_NAME_ATTR_TYPE, 0, const_cast<char*>(szOID_COMMON_NAME), &CommonName[0], dwCommonNameLength);
	return DnsNameMatches(RequiredName, CommonName.c_str());
}

// Select, and return a handle to a server certificate located by name
// Usually used for a best guess at a certificate to be used as the SSL certificate for a server 
SECURITY_STATUS CertFindServerCertificateByName(PCCERT_CONTEXT & pCertContext, LPCWSTR pszSubjectName, bool fUserStore)
{
	HCERTSTORE hCertStore{};
	WCHAR pszFriendlyNameString[128];
	WCHAR	pszNameString[128];

	if (pszSubjectName == nullptr || wcsnlen(pszSubjectName, 1) == 0)
	{
		DebugMsg("**** No subject name specified!");
		return E_POINTER;
	}

	SECURITY_STATUS hr = GetStore(hCertStore, fUserStore);
	if (FAILED(hr))
		return hr;

	CertContextHandle hCertContext(pCertContext), hCertContextSaved;

	char * serverauth = const_cast<char*>(szOID_PKIX_KP_SERVER_AUTH);
	CERT_ENHKEY_USAGE eku;
	eku.cUsageIdentifier = 1;
	eku.rgpszUsageIdentifier = &serverauth;
	// Find a server certificate. Note that this code just searches for a 
	// certificate that has the required enhanced key usage for server authentication
	// it then selects the best one (ideally one that contains the server name
	// in the subject name).

	while (nullptr != (pCertContext = CertFindCertificateInStore(hCertStore,
		X509_ASN_ENCODING,
		CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG,
		CERT_FIND_ENHKEY_USAGE,
		&eku,
		pCertContext))) // If this points to a valid certificate it will act as starting point and also be closed
	{
		//ShowCertInfo(pCertContext);
		if (!CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, pszFriendlyNameString, _countof(pszFriendlyNameString)))
		{
			DebugMsg("CertGetNameString failed getting friendly name.");
			continue;
		}
 		DebugMsg("Certificate %p '%S' is allowed to be used for server authentication.", pCertContext, pszFriendlyNameString);
		if (!CertGetNameString(pCertContext, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, pszNameString, _countof(pszNameString)))
			DebugMsg("CertGetNameString failed getting subject name.");
		else if (!MatchCertificateName(pCertContext, pszSubjectName))  //  (_tcscmp(pszNameString, pszSubjectName))
			DebugMsg("Certificate %p has wrong subject name.", pCertContext);
		else if (CertCompareCertificateName(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, &pCertContext->pCertInfo->Issuer))
		{
			if (!hCertContextSaved)
			{
				DebugMsg("Self-signed certificate %p was found and saved in case it is needed.", pCertContext);
				hCertContextSaved.attach(CertDuplicateCertificateContext(pCertContext));
			}
		}
		else
		{
			DebugMsg("Certificate is acceptable.");
			break;
		}
	}

	if (pCertContext) // This means we exited after finding a perfect certificate
	{
		DebugMsg("Attaching context %p", pCertContext);
		hCertContext.attach(pCertContext);
	}

	if (hCertContextSaved && !hCertContext)
	{	// We have a saved self-signed certificate and nothing better 
		DebugMsg("Self-signed certificate %p was the best we had.", hCertContextSaved.get());
		hCertContext = std::move(hCertContextSaved);
	}

	if (hCertContext)
	{
		pCertContext = hCertContext.detach();
		DebugMsg("CertFindServerCertificateByName returning context %p", pCertContext);
	}
	else
	{
		DWORD LastError = GetLastError();
		if (LastError == CRYPT_E_NOT_FOUND)
		{
			DebugMsg("**** CertFindCertificateInStore did not find a certificate, creating one");
			pCertContext = CreateCertificate(!fUserStore, pszSubjectName); // No need to specify, makes server cert by default
			if (!pCertContext)
			{
				LastError = GetLastError();
				DebugMsg("**** Error 0x%.8x returned by CreateCertificate", LastError);
				std::cout << "Could not create certificate, are you running as administrator?" << std::endl;
				return HRESULT_FROM_WIN32(LastError);
			}
		}
		else
		{
			DebugMsg("**** Error 0x%.8x returned by CertFindCertificateInStore", LastError);
			return HRESULT_FROM_WIN32(LastError);
		}
	}

	return SEC_E_OK;
}

// Select, and return a handle to a client certificate
// We take a best guess at a certificate to be used as the SSL certificate for this client 
SECURITY_STATUS CertFindClientCertificate(PCCERT_CONTEXT & pCertContext, const LPCWSTR pszSubjectName, bool fUserStore)
{
	HCERTSTORE hCertStore;
	WCHAR pszFriendlyNameString[128];
	WCHAR	pszNameString[128];

	SECURITY_STATUS hr = GetStore(hCertStore, fUserStore);
	if (FAILED(hr))
		return hr;


	if (pCertContext)	// The caller passed in a certificate context we no longer need, so free it
		CertFreeCertificateContext(pCertContext);
	pCertContext = nullptr;

	char * requiredUsage = const_cast<char*>(szOID_PKIX_KP_CLIENT_AUTH);
	CERT_ENHKEY_USAGE eku;
	PCCERT_CONTEXT pCertContextCurrent = nullptr;
	eku.cUsageIdentifier = 1;
	eku.rgpszUsageIdentifier = &requiredUsage;
	// Find a client certificate. Note that this code just searches for a 
	// certificate that has the required enhanced key usage for server authentication
	// it then selects the best one (ideally one that contains the client name somewhere
	// in the subject name).

	while (nullptr != (pCertContextCurrent = CertFindCertificateInStore(hCertStore,
		X509_ASN_ENCODING,
		CERT_FIND_OPTIONAL_ENHKEY_USAGE_FLAG,
		CERT_FIND_ENHKEY_USAGE,
		&eku,
		pCertContextCurrent)))
	{
		//ShowCertInfo(pCertContext);
		if (!CertGetNameString(pCertContextCurrent, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, pszFriendlyNameString, _countof(pszFriendlyNameString)))
		{
			DebugMsg("CertGetNameString failed getting friendly name.");
			continue;
		}
		DebugMsg("Certificate '%S' is allowed to be used for client authentication.", pszFriendlyNameString);
		if (!CertGetNameString(pCertContextCurrent, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, nullptr, pszNameString, _countof(pszNameString)))
		{
			DebugMsg("CertGetNameString failed getting subject name.");
			continue;
		}
		DebugMsg("   Subject name = %S.", pszNameString);
		// We must be able to access cert's private key
		HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hCryptProvOrNCryptKey = NULL;
		BOOL fCallerFreeProvOrNCryptKey = FALSE;
		DWORD dwKeySpec;
		if (!CryptAcquireCertificatePrivateKey(pCertContextCurrent, 0, nullptr, &hCryptProvOrNCryptKey, &dwKeySpec, &fCallerFreeProvOrNCryptKey))
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
		if (pszSubjectName && wcsncmp(pszNameString, pszSubjectName, _countof(pszNameString)))
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

SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo, bool fUserStore)
{
	if (pCertContext)
	{ // The caller passed in a certificate context we no longer need, so free it
		CertFreeCertificateContext(pCertContext);
		pCertContext = nullptr;
	}
	PCCERT_CHAIN_CONTEXT pChainContext = nullptr;
	CERT_CHAIN_FIND_BY_ISSUER_PARA FindByIssuerPara = { 0 };
	SECURITY_STATUS Status = SEC_E_CERT_UNKNOWN;
	HCERTSTORE hCertStore;
	SECURITY_STATUS hr = GetStore(hCertStore, fUserStore);
	if (FAILED(hr))
		return hr;

	//
	// Enumerate possible client certificates.
	//

	FindByIssuerPara.cbSize = sizeof(FindByIssuerPara);
	FindByIssuerPara.pszUsageIdentifier = szOID_PKIX_KP_CLIENT_AUTH;
	FindByIssuerPara.dwKeySpec = 0;
	FindByIssuerPara.cIssuer = IssuerListInfo.cIssuers;
	FindByIssuerPara.rgIssuer = IssuerListInfo.aIssuers;

	pChainContext = nullptr;

	while (true)
	{
		// Find a certificate chain.
		pChainContext = CertFindChainInStore(hCertStore,
			X509_ASN_ENCODING,
			0,
			CERT_CHAIN_FIND_BY_ISSUER,
			&FindByIssuerPara,
			pChainContext);
		if (pChainContext == nullptr)
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
		if (g_ShowCertInfo && debug && pCertContext)
			ShowCertInfo(pCertContext, L"Certificate at the end of the chain selected");
		CertFreeCertificateChain(pChainContext);
		Status = SEC_E_OK;
		break;
	}
	return Status;
}


// Simple certificate search by name only

HRESULT CertFindByName(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName, bool fUserStore)
{
	if (pCertContext)
	{ // The caller passed in a certificate context we no longer need, so free it
		CertFreeCertificateContext(pCertContext);
		pCertContext = nullptr;
	}
	HCERTSTORE hCertStore;
	SECURITY_STATUS hr = GetStore(hCertStore, fUserStore);
	if (FAILED(hr))
		return hr;

	// Find a client certificate. Note that this code just searches for a 
	// certificate that contains the name somewhere in the subject name.
	// If we ever really start using user names there's probably a better scheme.
	//
	// If a subject name is not specified just return a null credential.
	//

	if (pszSubjectName)
	{
		pCertContext = CertFindCertificateInStore(hCertStore,
			X509_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_STR,
			pszSubjectName,
			nullptr);
		if (pCertContext)
		{
			return S_OK;
		}
		else
		{
			DWORD Err = GetLastError();
			DebugMsg("**** Error 0x%.8x returned by CertFindCertificateInStore", Err);
			return HRESULT_FROM_WIN32(Err);
		}
	}
	else
		return S_FALSE; // Succeeded, but not S_OK
}
// Utility functions to help with certificates

int hex_char_to_int(char c) {
	int result = -1;
	if (('0' <= c) && (c <= '9')) {
		result = c - '0';
	}
	else if (('A' <= c) && (c <= 'F')) {
		result = 10 + c - 'A';
	}
	else if (('a' <= c) && (c <= 'f')) {
		result = 10 + c - 'a';
	}
	return result;
}

std::vector<byte> hexToBinary(const char * const str)
{
	std::vector<byte> boutput(20);
	byte byteValue = 0;
	auto it = boutput.begin();
	const char * p = str;
	bool highOrder = false;

	while (*p != 0 && str - p < 40 && it != boutput.end())
	{
		const auto nibbleValue = static_cast<byte>(hex_char_to_int(*p++));
		if (nibbleValue >= 0)
		{
			highOrder = !highOrder;
			if (highOrder)
			{
				byteValue = nibbleValue << 4;
			}
			else
			{
				*it = byteValue | nibbleValue;
				it++;
			}
		}
	}
	return boutput;
}

// Section of code supporting CertFindCertificateUI which uses CryptUIDlgSelectCertificate a function 
// that is not exported, so you have to link to it dynamically. Also various required structures and
// methods are not in the header file, so they have to be declared.

using PFNCCERTDISPLAYPROC =
BOOL(WINAPI *)(
	_In_ PCCERT_CONTEXT	pCertContext,
	_In_ HWND			hWndSelCertDlg,
	_In_ void			*pvCallbackData
	);

typedef struct _CRYPTUI_SELECTCERTIFICATE_STRUCT {
	DWORD				dwSize;
	HWND				hwndParent;
	DWORD				dwFlags;
	LPCTSTR				szTitle;
	DWORD				dwDontUseColumn;
	LPCTSTR				szDisplayString;
	PFNCFILTERPROC		pFilterCallback;
	PFNCCERTDISPLAYPROC	pDisplayCallback;
	void				*pvCallbackData;
	DWORD				cDisplayStores;
	HCERTSTORE			*rghDisplayStores;
	DWORD				cStores;
	HCERTSTORE			*rghStores;
	DWORD				cPropSheetPages;
	LPCPROPSHEETPAGE	rgPropSheetPages;
	HCERTSTORE			hSelectedCertStore;
} CRYPTUI_SELECTCERTIFICATE_STRUCT, *PCRYPTUI_SELECTCERTIFICATE_STRUCT;

using CryptUIDlgSelectCertificate = PCCERT_CONTEXT(WINAPI *) (PCRYPTUI_SELECTCERTIFICATE_STRUCT pcsc);

// Make sure the certificate is a valid server certificate, for example, does the name match, do you have a private key,
// is the certificate allowed to be used for server identification

BOOL WINAPI ValidServerCert(
	PCCERT_CONTEXT	pCertContext,
	BOOL			*pfInitialSelectedCert,
	void			*pvCallbackData // Passes in the required name
)
{
	UNREFERENCED_PARAMETER(pfInitialSelectedCert);
	DWORD cbData = 0;
	std::wstring s = std::wstring(L"Certificate '") + GetCertName(pCertContext) + L"' ";
	if (!MatchCertificateName(pCertContext, (LPCWSTR)pvCallbackData))  //  (_tcscmp(pszNameString, pszSubjectName))
		s.append(L"has wrong subject name.");
	else if (!CertGetCertificateContextProperty(pCertContext, CERT_KEY_PROV_INFO_PROP_ID, nullptr, &cbData) && GetLastError() == CRYPT_E_NOT_FOUND)
	{
		s.append(L"has no private key.");
	}
	else
	{  // All checks passed now check Enhanced Key Usage
		cbData = 0;
		CertGetEnhancedKeyUsage(pCertContext, 0, nullptr, &cbData);
		if (cbData == 0)
			return TRUE; // There are no EKU entries, so any usage is allowed
		else
		{
			std::vector<byte> Data(cbData);
			auto peku = (PCERT_ENHKEY_USAGE)(&Data[0]);
			CertGetEnhancedKeyUsage(pCertContext, 0, peku, &cbData);
			LPSTR* szUsageID = peku->rgpszUsageIdentifier;
			for (DWORD i = 0; i < peku->cUsageIdentifier; i++)
			{
				if (!strcmp(*szUsageID, szOID_PKIX_KP_SERVER_AUTH))
					return TRUE; // All checks passed and the certificate is allowed to be used for server identification
				szUsageID++;
			}
		s.append(L"is not allowed use for server authentication.");
		}
	}
	// One of the checks failed
	DebugMsg(s.c_str());
	return FALSE;
}

// CryptUIDlgSelectCertificateW is not in a library, but IS present in CryptUI.dll so we
// have to link to it dynamically. This is the declaration of the function pointer.

CryptUIDlgSelectCertificate SelectCertificate = nullptr;

SECURITY_STATUS CertFindServerCertificateUI(PCCERT_CONTEXT & pCertContext, LPCWSTR pszSubjectName, bool fUserStore)
{
	//   Open a certificate store.
	HCERTSTORE hCertStore;
	SECURITY_STATUS hr = GetStore(hCertStore, fUserStore);
	if (FAILED(hr))
		return hr;

	if (pCertContext)	// The caller passed in a certificate context we no longer need, so free it
	{
		CertFreeCertificateContext(pCertContext);
		pCertContext = nullptr;
	}

	// Link to SelectCertificate if it has not already been done

	if (!SelectCertificate)
	{  // Not linked yet, find the function in the DLL
		HINSTANCE CryptUIDLL = LoadLibrary(L"CryptUI.dll");
		if (CryptUIDLL)
			SelectCertificate = (CryptUIDlgSelectCertificate)GetProcAddress(CryptUIDLL, "CryptUIDlgSelectCertificateW");
		else
			return E_NOINTERFACE;
		// Do not call FreeLibrary because the function may be called again later
	}

	// Display a list of the certificates in the store and allow the user to select a certificate.
	// Note that only certificates which pass the test defined in ValidCert (if any) will be displayed.

	CRYPTUI_SELECTCERTIFICATE_STRUCT csc{};
	HCERTSTORE tempStore = hCertStore; // A kludge depending on rghDisplayStores being readonly later on.

	csc.dwSize = sizeof csc;
	csc.szTitle = L"Select a Server Certificate";
	csc.dwDontUseColumn = CRYPTUI_SELECT_LOCATION_COLUMN;
	csc.pFilterCallback = ValidServerCert;
	csc.cDisplayStores = 1;
	csc.rghDisplayStores = &tempStore;
	csc.pvCallbackData = (LPVOID)pszSubjectName;

	if ((pCertContext = SelectCertificate(&csc))==nullptr)
		DebugMsg("Select Certificate UI did not return a certificate.");

	return pCertContext ? SEC_E_OK : SEC_E_CERT_UNKNOWN;
}

// End Section of code supporting CertFindCertificateUI

SECURITY_STATUS CertFindCertificateBySignature(PCCERT_CONTEXT & pCertContext, char const * const signature, bool fUserStore)
{
	// Find a specific certificate based on its signature
	// The parameter is the SHA1 signatureof the certificate you want the server to use in string form, which the certificate manager will show you as the "thumbprint" field
	auto b = hexToBinary(signature);

	if (b.size() != 20)
	{
		DebugMsg("Certificate signature length should be exactly 20 bytes. \n");
		return SEC_E_INVALID_PARAMETER;
	}
	//   Open a certificate store.
	HCERTSTORE hCertStore;
	SECURITY_STATUS hr = GetStore(hCertStore, fUserStore);
	if (FAILED(hr))
		return hr;

	if (pCertContext)	// The caller passed in a certificate context we no longer need, so free it
	{
		CertFreeCertificateContext(pCertContext);
		pCertContext = nullptr;
	}

	CRYPT_HASH_BLOB certhash;
	certhash.cbData = static_cast<decltype(certhash.cbData)>(b.size());
	certhash.pbData = &b[0];

	// Now search the selected store for the certificate
	if ((pCertContext = CertFindCertificateInStore(
		hCertStore,
		X509_ASN_ENCODING,             // Use X509_ASN_ENCODING
		0,                            // No dwFlags needed 
		CERT_FIND_SHA1_HASH, // Find a certificate with a SHA1 hash that matches the next parameter
		&certhash,
		nullptr)) !=nullptr)                        // NULL for the first call to the
	{
		WCHAR pszFriendlyNameString[128];
		//ShowCertInfo(pCertContext);
		if (!CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, pszFriendlyNameString, _countof(pszFriendlyNameString)))
		{
			DebugMsg("CertGetNameString failed getting friendly name.");
			return HRESULT_FROM_WIN32(GetLastError());
		}
		DebugMsg("CertFindCertificateBySignature found certificate '%S' is allowed to be used for server authentication.", (LPWSTR)pszFriendlyNameString);
		if (CertCompareCertificateName(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, &pCertContext->pCertInfo->Issuer))
			DebugMsg("A self-signed certificate was found.");
	}
	else
	{
		DebugMsg("CertFindCertificateBySignature could not find the desired certificate.\n");
		return SEC_E_CERT_UNKNOWN;
	}
	return SEC_E_OK;
}

// Return an indication of whether a certificate is trusted by asking Windows to validate the
// trust chain (basically asking is the certificate issuer trusted)
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext, const bool isClientCert)
{
	HTTPSPolicyCallbackData  polHttps{ 0 };
	CERT_CHAIN_POLICY_PARA   PolicyPara{ 0 };
	CERT_CHAIN_POLICY_STATUS PolicyStatus{ 0 };
	CERT_CHAIN_PARA          ChainPara{ 0 };
	PCCERT_CHAIN_CONTEXT     pChainContext = nullptr;
	HRESULT                  Status;
	LPSTR rgszUsages[] = { const_cast<char*>(isClientCert ? szOID_PKIX_KP_CLIENT_AUTH : szOID_PKIX_KP_SERVER_AUTH),
	   const_cast<char*>(szOID_SERVER_GATED_CRYPTO),
	   const_cast<char*>(szOID_SGC_NETSCAPE) };
	DWORD cUsages = _countof(rgszUsages);

	// Build certificate chain.
	ChainPara.cbSize = sizeof(ChainPara);
	ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	ChainPara.RequestedUsage.Usage.cUsageIdentifier = cUsages;
	ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = rgszUsages;

	if (!CertGetCertificateChain(nullptr,
		pCertContext,
		nullptr,
		pCertContext->hCertStore,
		&ChainPara,
		0,
		nullptr,
		&pChainContext))
	{
		Status = GetLastError();
		DebugMsg("Error %#x returned by CertGetCertificateChain!", Status);
		goto cleanup;
	}


	// Validate certificate chain.
	polHttps.cbStruct = sizeof(HTTPSPolicyCallbackData);
	polHttps.dwAuthType = isClientCert ? AUTHTYPE_CLIENT : AUTHTYPE_SERVER;
	polHttps.fdwChecks = 0;    // dwCertFlags;
	polHttps.pwszServerName = nullptr; // ServerName - checked elsewhere

	PolicyPara.cbSize = sizeof(PolicyPara);
	PolicyPara.pvExtraPolicyPara = &polHttps;

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
		DebugMsg("PolicyStatus error %#x returned by CertVerifyCertificateChainPolicy!", PolicyStatus.dwError);
		goto cleanup;
	}

	Status = SEC_E_OK;

cleanup:
	if (pChainContext)
		CertFreeCertificateChain(pChainContext);

	return Status;
}

// Helper function to return the friendly name of a certificate so it can be showed to a human 
std::wstring GetCertName(PCCERT_CONTEXT pCertContext)
{
	std::wstring certName;
	certName.resize(128);
  auto good = CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, &certName[0], static_cast<DWORD>(certName.capacity()));
	if (good)
	{
		certName.resize(certName.find(L'\0')); // throw away characters after null
		return certName;
	}
	else
		return L"<unknown>";
}

// Display a UI with the certificate info and also write it to the debug output
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, std::wstring Title)
{
	WCHAR pszNameString[256] {};
	void*            pvData;
	DWORD            cbData {};
	DWORD            dwPropId = 0;


	//  Display the certificate.
	if (!CryptUIDlgViewContext(
		CERT_STORE_CERTIFICATE_CONTEXT,
		pCertContext,
		nullptr,
		Title.c_str(),
		0,
		pszNameString // Dummy parameter just to avoid a warning
	))
	{
		DebugMsg("UI failed.");
	}

	if (CertGetNameString(
		pCertContext,
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		nullptr,
		pszNameString,
		128))
	{
		DebugMsg("Certificate for %S", pszNameString);
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
			nullptr,
			&cbData))
		{
			//  Continue.
		}
		else
		{
			// If the first call to the function failed,
			// exit to an error routine.
			DebugMsg("Call #1 to CertGetCertificateContextProperty failed.");
			return E_FAIL;
		}
		//-------------------------------------------------------------------
		// The call succeeded. Use the size to allocate memory 
		// for the property.
		if (cbData > 0)
		{
			std::vector<char> propertydata(cbData);
			pvData = propertydata.data();
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
				DebugMsg("Call #2 to CertGetCertificateContextProperty failed.");
				return E_FAIL;
			}
			//---------------------------------------------------------------
			// Show the results.

			DebugMsg("The Property Content is");
			PrintHexDump(cbData, pvData);
		}
		else
		{
			DebugMsg("The Property is empty");
		}
	}
	return S_OK;
}

// based on a sample found at:
// http://blogs.msdn.com/b/alejacma/archive/2009/03/16/how-to-create-a-self-signed-certificate-with-cryptoapi-c.aspx
// Create a self-signed certificate and store it in the machine personal store
PCCERT_CONTEXT CreateCertificate(bool useMachineStore, LPCWSTR Subject, LPCWSTR FriendlyName, LPCWSTR Description, bool forClient)
{
	// CREATE KEY PAIR FOR SELF-SIGNED CERTIFICATE IN MACHINE PROFILE
	CryptProvider cryptprovider;
	CryptKey key;
	DWORD KeyFlags = useMachineStore ? CRYPT_MACHINE_KEYSET : 0;
	// Acquire key container
	DebugMsg(("CryptAcquireContext of existing key container... "));
	if (!cryptprovider.AcquireContext(KeyFlags))
	{
		int err = GetLastError();

		if (err == NTE_BAD_KEYSET)
			DebugMsg("**** CryptAcquireContext failed with 'bad keyset'");
		else
			DebugMsg("**** Error 0x%.8x returned by CryptAcquireContext", err);

		// Try to create a new key container
		DebugMsg(("CryptAcquireContext create new container... "));
		if (!cryptprovider.AcquireContext(CRYPT_NEWKEYSET | CRYPT_MACHINE_KEYSET))
		{
			err = GetLastError();

			if (err == NTE_EXISTS)
				DebugMsg("**** CryptAcquireContext failed with 'already exists', are you running as administrator");
			else
				DebugMsg("**** Error 0x%.8x returned by CryptAcquireContext", err);
			// Error
			DebugMsg("Error 0x%.8x", GetLastError());
			return nullptr;
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
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}
	else
		DebugMsg("Success");

	// Create self-signed certificate and add it to personal store in machine or user profile

	std::vector<BYTE> CertName;

	// Encode certificate Subject
	std::wstring X500(L"CN=");
	if (Subject)
		X500 += Subject;
	else
		X500 += L"localuser";
	DWORD cbEncoded = 0;
	// Find out how many bytes are needed to encode the certificate
	DebugMsg(("CertStrToName... "));
	if (CertStrToName(X509_ASN_ENCODING, X500.c_str(), CERT_X500_NAME_STR, nullptr, nullptr, &cbEncoded, nullptr))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}
	// Allocate the required space
	CertName.resize(cbEncoded);
	// Encode the certificate
	DebugMsg(("CertStrToName... "));
	if (CertStrToName(X509_ASN_ENCODING, X500.c_str(), CERT_X500_NAME_STR, nullptr, &CertName[0], &cbEncoded, nullptr))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}

	// Prepare certificate Subject for self-signed certificate
	CERT_NAME_BLOB SubjectIssuerBlob{ 0 };
	SubjectIssuerBlob.cbData = cbEncoded;
	SubjectIssuerBlob.pbData = &CertName[0];

	// Prepare key provider structure for certificate
	CRYPT_KEY_PROV_INFO KeyProvInfo{ nullptr };
	KeyProvInfo.pwszContainerName = cryptprovider.KeyContainerName;
	KeyProvInfo.pwszProvName = nullptr;
	KeyProvInfo.dwProvType = PROV_RSA_FULL;
	KeyProvInfo.dwFlags = CRYPT_MACHINE_KEYSET;
	KeyProvInfo.cProvParam = 0;
	KeyProvInfo.rgProvParam = nullptr;
	KeyProvInfo.dwKeySpec = AT_SIGNATURE;

	// Prepare algorithm structure for certificate
	CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm{ nullptr };
	SignatureAlgorithm.pszObjId = const_cast<char*>(szOID_RSA_SHA1RSA);

	// Prepare Expiration date for certificate
	SYSTEMTIME EndTime;
	GetSystemTime(&EndTime);
	EndTime.wYear += 5;

	// Create certificate
	DebugMsg(("CertCreateSelfSignCertificate... "));
	CertContextHandle pCertContext(CertCreateSelfSignCertificate(NULL, &SubjectIssuerBlob, 0, &KeyProvInfo, &SignatureAlgorithm, nullptr, &EndTime, nullptr));
	if (pCertContext)
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}

	// Specify the allowed usage of the certificate (client or server authentication)
	DebugMsg(("CertAddEnhancedKeyUsageIdentifier"));
	if (CertAddEnhancedKeyUsageIdentifier(pCertContext.get(), forClient ? szOID_PKIX_KP_CLIENT_AUTH : szOID_PKIX_KP_SERVER_AUTH))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}

	// Common variable used in several calls below
	CRYPT_DATA_BLOB cdblob;

	// Give the certificate a friendly name
	if (FriendlyName)
		cdblob.pbData = (BYTE*)FriendlyName;
	else
		cdblob.pbData = (BYTE*)L"SSLStream Testing";
		cdblob.cbData = static_cast<decltype(cdblob.cbData)>((wcslen((LPWSTR)cdblob.pbData) + 1) * sizeof(WCHAR));
	DebugMsg(("CertSetCertificateContextProperty CERT_FRIENDLY_NAME_PROP_ID"));
	if (CertSetCertificateContextProperty(pCertContext.get(), CERT_FRIENDLY_NAME_PROP_ID, 0, &cdblob))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}

	// Give the certificate a description
	if (Description)
		cdblob.pbData = (BYTE*)Description;
	else if (forClient)
		cdblob.pbData = (BYTE*)L"SSL Stream Client Test created automatically";
	else
		cdblob.pbData = (BYTE*)L"SSLStream Server Test created automatically";
		cdblob.cbData = static_cast<decltype(cdblob.cbData)>((wcslen((LPWSTR)cdblob.pbData) + 1) * sizeof(WCHAR));
	DebugMsg(("CertSetCertificateContextProperty CERT_DESCRIPTION_PROP_ID"));
	if (CertSetCertificateContextProperty(pCertContext.get(), CERT_DESCRIPTION_PROP_ID, 0, &cdblob))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}

	// Open Personal certificate store for whole machine or individual user
	DebugMsg(("Opening  root store for writingusing CertOpenStore"));
	CertStore store;
	if (store.CertOpenStore(useMachineStore ? CERT_SYSTEM_STORE_LOCAL_MACHINE : CERT_SYSTEM_STORE_CURRENT_USER))
		DebugMsg("CertOpenStore succeeded");
	else
	{
		// Error
		int err = GetLastError();

		if (err == ERROR_ACCESS_DENIED)
			DebugMsg("**** CertOpenStore failed with 'access denied' are  you running as administrator?");
		else
			DebugMsg("**** Error 0x%.8x returned by CertOpenStore", err);
		return nullptr;
	}
	// Add the cert to the store
	DebugMsg(("CertAddCertificateContextToStore... "));
	if (store.AddCertificateContext(pCertContext.get()))
		DebugMsg("Success");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}

	// Just for testing, verify that we can access cert's private key
	DebugMsg(("CryptAcquireCertificatePrivateKey... "));
	CSP csp;
	if (csp.AcquirePrivateKey(pCertContext.get()))
		DebugMsg("Success, private key acquired");
	else
	{
		// Error
		DebugMsg("Error 0x%.8x", GetLastError());
		return nullptr;
	}
	return pCertContext.detach();
}
