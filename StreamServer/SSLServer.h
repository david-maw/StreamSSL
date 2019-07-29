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

class CListener;

class CSSLServer : public ISocketStream
{
public:
	// The constructor is private, the only way to get hold of a CSSLServer is by calling Create.
	// This call is normally from a CListener.
	static CSSLServer* Create(SOCKET s, CListener* Listener);
	~CSSLServer();
	int RecvPartial(void * const lpBuf, const size_t Len) override;
	int SendPartial(const void * const lpBuf, const size_t Len) override;
	ISocketStream* GetSocketStream();
	DWORD GetLastError() const override;
	HRESULT Disconnect() override;
	static PSecurityFunctionTable SSPI();
	// Set up state for this connection
	HRESULT Initialize(const void * const lpBuf = nullptr, const size_t Len = 0);
	std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)> SelectServerCert;
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> ClientCertAcceptable;
	CListener* GetListener() const;
	bool IsConnected{ false };

private:
	// Note, private constructor
	explicit CSSLServer(CPassiveSock*);
	CListener* m_Listener;
	CredHandle hServerCreds{};
	static PSecurityFunctionTable g_pSSPI;
	std::unique_ptr <CPassiveSock> m_SocketStream;
	int m_LastError{ 0 };
	static HRESULT InitializeClass();
	SECURITY_STATUS DecryptAndHandleConcatenatedShutdownMessage(SecBufferDesc& Message);
	int RecvEncrypted(void* const lpBuf, const size_t Len);
	bool SSPINegotiateLoop();
	static const int MaxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int MaxExtraSize = 50; // Also arbitrary, current SSL header is 5 bytes, trailer 36
	CHAR writeBuffer[MaxMsgSize + MaxExtraSize]{}; // Enough for a whole encrypted message
	CHAR readBuffer[(MaxMsgSize + MaxExtraSize) * 2]{}; // Enough for two whole messages so we don't need to move data around in buffers
	DWORD readBufferBytes{ 0 };
	void* readPtr{};
	SecurityContextHandle m_hContext;
	SecPkgContext_StreamSizes Sizes{};
	bool m_encrypting = false; // Is channel currently encypting
};