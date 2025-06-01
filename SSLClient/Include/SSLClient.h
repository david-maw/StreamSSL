#pragma once

#include "SecurityHandle.h"
#include "Common.h"
#include <functional>

class CActiveSock; // forward declaration

class CSSLClient : public CSSLCommon
{
public:
	explicit CSSLClient(CActiveSock*);
	~CSSLClient() = default;
	// ISocketStream Methods
	int Recv(LPVOID lpBuf, const size_t Len, const size_t MinLen = 1);
	int Send(LPCVOID lpBuf, const size_t Len);
	DWORD GetLastError() const;
	HRESULT Disconnect(bool closeUnderlyingSocket = true);
	void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds, bool NewTimerAutomatic = true);
	int GetRecvTimeoutSeconds() const;
	void SetSendTimeoutSeconds(int NewSendTimeoutSeconds, bool NewTimerAutomatic = true);
	int GetSendTimeoutSeconds() const;
	void StartRecvTimer();
	void StartSendTimer();
	std::wstring ServerName;
	// Regular class interface
	// Set up state for this connection
	HRESULT Initialize(std::wstring ServerName, const void * const lpBuf = nullptr, const int Len = 0);
	// Attributes
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)> ServerCertAcceptable;
	std::function<SECURITY_STATUS(PCCERT_CONTEXT &pCertContext, SecPkgContext_IssuerListInfoEx *pIssuerListInfo, bool Required)> SelectClientCertificate;
	bool getServerCertNameMatches() const;
	bool getServerCertTrusted() const;

private:
	CredentialHandle m_ClientCreds;
	CActiveSock *m_SocketStream;
	int m_LastError{ 0 };
	bool m_encrypting = false;
	static HRESULT InitializeClass();
	SECURITY_STATUS SSPINegotiate(LPCWCHAR ServerName);
	SECURITY_STATUS ActualSSPINegotiateLoop(LPCWCHAR ServerName, SecBuffer* pInitialBuffer = nullptr);
	int GetDataFromSocket();
	static const int MaxMsgSize = 16000; // Arbitrary but less than 16384 limit, including MaxExtraSize
	static const int MaxExtraSize = 50; // Also arbitrary, current header is 5 bytes, trailer 36
	CHAR writeBuffer[MaxMsgSize + MaxExtraSize]{}; // Enough for a whole encrypted message
	CHAR readBuffer[(MaxMsgSize + MaxExtraSize)  *2]{}; // Enough for two whole messages so we don't need to move data around in buffers
	size_t readBufferBytes = 0; // Bytes read from socket but not yet consumed
	CHAR plainText[MaxMsgSize  *2]{}; // Extra plaintext data not yet delivered
	CHAR *plainTextPtr = nullptr;
	size_t plainTextBytes = 0;
	void *readPtr = nullptr;
	SecurityContextHandle m_hContext;
	SecPkgContext_StreamSizes Sizes{};
	static SECURITY_STATUS CreateCredentialsFromCertificate(PCredHandle phCreds, const PCCERT_CONTEXT pCertContext);
	SECURITY_STATUS GetNewClientCredentials();
	int RecvPartialEncrypted(LPVOID lpBuf, const size_t Len);
	bool ServerCertNameMatches{ false };
	bool ServerCertTrusted{ false };
	HRESULT DisconnectSSL();
};
