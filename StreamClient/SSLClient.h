#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <functional>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#include <schannel.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")

class CActiveSock; // forward declaration

class CSSLClient
{
public:
	CSSLClient(CActiveSock *);
	~CSSLClient(void);
private:
   static PSecurityFunctionTable g_pSSPI;
	CredHandle m_ClientCreds;
	CActiveSock * m_SocketStream;
	int m_LastError;
	static HRESULT InitializeClass(void);
	HRESULT Startup(void);
	SECURITY_STATUS SSPINegotiateLoop(TCHAR* ServerName);
	static const int MaxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int MaxExtraSize = 50; // Also arbitrary, current header is 5 bytes, trailer 36
	CHAR writeBuffer[MaxMsgSize + MaxExtraSize]; // Enough for a whole encrypted message
	CHAR readBuffer[(MaxMsgSize + MaxExtraSize) * 2]; // Enough for two whole messages so we don't need to move data around in buffers
	DWORD readBufferBytes;
	CHAR plainText[MaxMsgSize*2]; // Extra plaintext data not yet delivered
	CHAR * plainTextPtr;
   DWORD plainTextBytes;
	void * readPtr;
	CtxtHandle m_hContext;
	SecPkgContext_StreamSizes Sizes;
   static SECURITY_STATUS CreateCredentialsFromCertificate(PCredHandle phCreds, const PCCERT_CONTEXT pCertContext);
   SECURITY_STATUS GetNewClientCredentials();
	bool ServerCertNameMatches;
	bool ServerCertTrusted;

public:
	// ISocketStream
	int RecvPartial(LPVOID lpBuf, const ULONG Len);
	int SendPartial (LPCVOID lpBuf, const ULONG Len);
	DWORD GetLastError(void);
	bool Close();
	// Regular class interface
	HRESULT Disconnect(void);
	static PSecurityFunctionTable SSPI(void);
	// Set up state for this connection
    HRESULT Initialize(LPCWSTR ServerName, const void * const lpBuf = NULL, const int Len = 0);
	// Attributes
    std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)> ServerCertAcceptable;
    std::function<SECURITY_STATUS (PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx * pIssuerListInfo)> SelectClientCertificate;
    bool getServerCertNameMatches();
	bool getServerCertTrusted();
};

