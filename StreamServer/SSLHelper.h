#pragma once
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include <schannel.h>
#include <cryptuiapi.h>
#pragma comment(lib,"cryptui.lib")
#ifndef SCH_USE_STRONG_CRYPTO // Needs KB 2868725 which is only in Windows 7+
#define SCH_USE_STRONG_CRYPTO                        0x00400000
#endif

// handy functions declared in this file
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title);
HRESULT CertTrusted(PCCERT_CONTEXT pCertContext);
SECURITY_STATUS CertFindCertificateUI(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName, boolean fUserStore = false); 
SECURITY_STATUS CertFindServerCertificateByName(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName, boolean fUserStore = false);
SECURITY_STATUS CertFindCertificateBySignature(PCCERT_CONTEXT & pCertContext, char const * const signature, boolean fUserStore = false);
CString GetHostName(COMPUTER_NAME_FORMAT WhichName = ComputerNameDnsHostname);
CString GetUserName(void);
CString GetCertName(PCCERT_CONTEXT pCertContext);

class CSSLHelper
{
private:
   const byte * const OriginalBufPtr;
   const byte * DataPtr; // Points to data inside message
   const byte * BufEnd;
   const int MaxBufBytes;
   UINT8 contentType, major, minor;
   UINT16 length;
   UINT8 handshakeType;
   UINT16 handshakeLength;
   bool CanDecode();
   bool decoded;
public:
   CSSLHelper(const byte * BufPtr, const int BufBytes);
	~CSSLHelper();
	// Max length of handshake data buffer
	void TraceHandshake();
   // Is this packet a complete client initialize packet
   bool IsClientInitialize();
   // Get SNI provided hostname
   CString GetSNI();
};
