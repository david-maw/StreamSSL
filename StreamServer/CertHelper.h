#pragma once
#include <schannel.h>
bool MatchCertificateName(PCCERT_CONTEXT pCertContext, LPCWSTR pszRequiredName);
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, std::wstring Title);
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext, const bool isClientCert);
std::wstring GetCertName(PCCERT_CONTEXT pCertContext);
SECURITY_STATUS CertFindClientCertificate(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName = nullptr, boolean fUserStore = true);
SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo);
SECURITY_STATUS CertFindServerCertificateUI(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName, boolean fUserStore = false);
SECURITY_STATUS CertFindServerCertificateByName(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName, boolean fUserStore = false);
SECURITY_STATUS CertFindCertificateBySignature(PCCERT_CONTEXT & pCertContext, char const * const signature, boolean fUserStore = false);

HRESULT CertFindByName(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName);

// defined in source file CreateCertificate.cpp
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCWSTR Subject = nullptr, LPCWSTR FriendlyName = nullptr, LPCWSTR Description = nullptr, bool forClient = false);
