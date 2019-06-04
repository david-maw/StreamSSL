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
#include "SecurityHandle.h"


class CActiveSock; // forward declaration

class CSSLClient
{
public:
	CSSLClient(CActiveSock *);
	~CSSLClient(void);
private:
	static PSecurityFunctionTable g_pSSPI;
	CredentialHandle m_ClientCreds;
	CActiveSock * m_SocketStream;
	int m_LastError;
	bool m_encrypting = false;
	static HRESULT InitializeClass(void);
	HRESULT Startup(void);
	SECURITY_STATUS SSPINegotiateLoop(WCHAR* ServerName);
	static const int MaxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int MaxExtraSize = 50; // Also arbitrary, current header is 5 bytes, trailer 36
	CHAR writeBuffer[MaxMsgSize + MaxExtraSize]{}; // Enough for a whole encrypted message
	CHAR readBuffer[(MaxMsgSize + MaxExtraSize) * 2]{}; // Enough for two whole messages so we don't need to move data around in buffers
	DWORD readBufferBytes = 0;
	CHAR plainText[MaxMsgSize * 2]{}; // Extra plaintext data not yet delivered
	CHAR * plainTextPtr =  nullptr;
	DWORD plainTextBytes = 0;
	void * readPtr = nullptr;
	SecurityContextHandle m_hContext;
	SecPkgContext_StreamSizes Sizes{};
	static SECURITY_STATUS CreateCredentialsFromCertificate(PCredHandle phCreds, const PCCERT_CONTEXT pCertContext);
	SECURITY_STATUS GetNewClientCredentials();
	int RecvPartialEncrypted(LPVOID lpBuf, const ULONG Len);
	bool ServerCertNameMatches;
	bool ServerCertTrusted;

public:
	// ISocketStream
	int RecvPartial(LPVOID lpBuf, const ULONG Len);
	int SendPartial(LPCVOID lpBuf, const ULONG Len);
	DWORD GetLastError(void);
	bool Close(bool closeUnderlyingSocket = true);
	// Regular class interface
	HRESULT Disconnect(void);
	static PSecurityFunctionTable SSPI(void);
	// Set up state for this connection
	HRESULT Initialize(LPCWSTR ServerName, const void * const lpBuf = NULL, const int Len = 0);
	// Attributes
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)> ServerCertAcceptable;
	std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx * pIssuerListInfo, bool Required)> SelectClientCertificate;
	bool getServerCertNameMatches();
	bool getServerCertTrusted();
};