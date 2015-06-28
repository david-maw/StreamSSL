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
// handy functions declared in this file
HRESULT ShowCertInfo(PCCERT_CONTEXT pCertContext, CString Title);
HRESULT CreateCredentials(LPCTSTR pszSubjectName, PCredHandle phCreds, boolean fMachineStore = false);


