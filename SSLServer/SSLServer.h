#pragma once
#include "PassiveSock.h"
#include "SecurityHandle.h"

#include <functional>

class CListener;

class CSSLServer : public ISocketStream
{
public:
	// The constructor is private, the only way to get hold of a CSSLServer is by calling Create.
	// This call is normally from a CListener.
	static CSSLServer* Create(SOCKET s, CListener* Listener);
	~CSSLServer();
	// ISocketStream functions
	int Recv(LPVOID lpBuf, const size_t Len, const size_t MinLen = 1) override;
	int Send(LPCVOID lpBuf, const size_t Len) override;
	DWORD GetLastError() const override;
	HRESULT Disconnect(bool CloseUnderlyingConnection) override;
	void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds, bool NewTimerAutomatic = true) override;
	int GetRecvTimeoutSeconds() const override;
	void SetSendTimeoutSeconds(int NewSendTimeoutSeconds, bool NewTimerAutomatic = true) override;
	int GetSendTimeoutSeconds() const override;
	void StartRecvTimer() override;
	void StartSendTimer() override;
	
	ISocketStream* GetSocketStream();
	static PSecurityFunctionTableW SSPI();
	// Set up state for this connection
	HRESULT Initialize(const void * const lpBuf = nullptr, const size_t Len = 0);
	std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)> SelectServerCert;
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> ClientCertAcceptable;
	CListener* GetListener() const;
	bool IsConnected{ false };

private:
	// Note, private constructor
	explicit CSSLServer(CPassiveSock *);
	HRESULT ShutDownSSL();
	CListener* m_Listener{ nullptr };
	CredHandle hServerCreds{};
	static PSecurityFunctionTableW g_pSSPI;
	std::unique_ptr<CPassiveSock> m_SocketStream;
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
	SecurityContextHandle m_hContext{};
	SecPkgContext_StreamSizes Sizes{};
	bool m_encrypting = false; // Is channel currently encypting
};
