#pragma once
#include "PassiveSock.h"
#include "SecurityHandle.h"

#include <functional>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
#include <wintrust.h>
#define SECURITY_WIN32
#include <security.h>
#pragma comment(lib, "secur32.lib")

class CSSLServer : public ISocketStream
{
public:
	explicit CSSLServer(CPassiveSock *);
	~CSSLServer();
	ISocketStream * getSocketStream();
	int RecvPartial(void * const lpBuf, const size_t Len) override;
	int SendPartial(const void * const lpBuf, const size_t Len) override;
	int GetLastError() override;
	HRESULT Disconnect() override;
	static PSecurityFunctionTable SSPI();
	// Set up state for this connection
	HRESULT Initialize(const void * const lpBuf = nullptr, const size_t Len = 0);
	std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)> SelectServerCert;
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> ClientCertAcceptable;
private:
	CredHandle hServerCreds{};
	static PSecurityFunctionTable g_pSSPI;
	CPassiveSock * m_SocketStream;
	int m_LastError{ 0 };
	static HRESULT InitializeClass();
	HRESULT Startup();
	void DecryptAndHandleConcatenatedShutdownMessage(SecBuffer(&Buffers)[4], SecBufferDesc& Message, int& err, SECURITY_STATUS& scRet);
	int RecvEncrypted(void* const lpBuf, const size_t Len);
	bool SSPINegotiateLoop();
	static const int MaxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int MaxExtraSize = 50; // Also arbitrary, current header is 5 bytes, trailer 36
	CHAR writeBuffer[MaxMsgSize + MaxExtraSize]{}; // Enough for a whole encrypted message
	CHAR readBuffer[(MaxMsgSize + MaxExtraSize) * 2]{}; // Enough for two whole messages so we don't need to move data around in buffers
	DWORD readBufferBytes{ 0 };
	void* readPtr{};
	SecurityContextHandle m_hContext;
	SecPkgContext_StreamSizes Sizes{};
	bool m_encrypting = false; // Is channel currently encypting
};