#pragma once
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")
#include "PassiveSock.h"

class CSSLServer : public ISocketStream
{
public:
	CSSLServer(CPassiveSock *);
	~CSSLServer(void);
	ISocketStream * getSocketStream(void);
	int Recv(void * const lpBuf, const int Len);
	int Send(const void * const lpBuf, const int Len);
	int GetLastError(void);
	HRESULT Disconnect(void);
	static PSecurityFunctionTable SSPI(void);
	// Set up state for this connection
	HRESULT Initialize(const void * const lpBuf = NULL, const int Len = 0);
private:
	static PSecurityFunctionTable g_pSSPI;
	static CredHandle g_ServerCreds;
   static CString g_ServerName;
	CPassiveSock * m_SocketStream;
	int m_LastError;
	static HRESULT InitializeClass(void);
	HRESULT Startup(void);
	bool SSPINegotiateLoop(void);
	static const int MaxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int MaxExtraSize = 50; // Also arbitrary, current header is 5 bytes, trailer 36
	CHAR writeBuffer[MaxMsgSize + MaxExtraSize]; // Enough for a whole encrypted message
	CHAR readBuffer[(MaxMsgSize + MaxExtraSize) * 2]; // Enough for two whole messages so we don't need to move data around in buffers
	DWORD readBufferBytes;
	void * readPtr;
	CtxtHandle      m_hContext;
	SecPkgContext_StreamSizes Sizes;
};

