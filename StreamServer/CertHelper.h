#pragma once
bool MatchCertificateName(PCCERT_CONTEXT pCertContext, LPCWSTR pszRequiredName);
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title);
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext, const bool forClient);
CString GetCertName(PCCERT_CONTEXT pCertContext);
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title);
SECURITY_STATUS CertFindClientCertificate(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName = NULL, boolean fUserStore = true);
SECURITY_STATUS CertFindFromIssuerList(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx & IssuerListInfo);
SECURITY_STATUS CertFindServerCertificateUI(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName, boolean fUserStore = false);
SECURITY_STATUS CertFindServerCertificateByName(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName, boolean fUserStore = false);
SECURITY_STATUS CertFindCertificateBySignature(PCCERT_CONTEXT & pCertContext, char const * const signature, boolean fUserStore = false);

HRESULT CertFindByName(PCCERT_CONTEXT & pCertContext, const LPCTSTR pszSubjectName);

// defined in source file CreateCertificate.cpp
PCCERT_CONTEXT CreateCertificate(bool MachineCert = false, LPCWSTR Subject = NULL, LPCWSTR FriendlyName = NULL, LPCWSTR Description = NULL, bool forClient = false);
