#pragma once
#include <wincrypt.h>
#include <functional>

class ISocketStream;

class CListener
{
public:
	enum class ErrorType {
		NoError,
		UnknownError,
		SocketInuse,
		SocketUnusable
	};
	CListener();
	~CListener();
private:
	SOCKET m_iListenSockets[FD_SETSIZE]{};
	HANDLE m_hSocketEvents[FD_SETSIZE]{};
	int m_iNumListenSockets{ 0 };
	CCriticalSection m_WorkerCountLock;
	uintptr_t m_ListenerThread { 0 };
	static void __cdecl Worker(LPVOID);
	static void __cdecl ListenerWorker(LPVOID);
	void Listen();
	std::function<void(ISocketStream * StreamSock)> m_actualwork;
public:
	static void LogWarning(const WCHAR* const);
	static void LogWarning(const CHAR* const);
	int m_WorkerCount{ 0 };
	CEvent m_StopEvent{ TRUE, FALSE };
	// Initialize the listener
	ErrorType Initialize(int TCPSocket);
	std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCWSTR pszSubjectName)> SelectServerCert;
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> ClientCertAcceptable;
	void EndListening();
	void BeginListening(std::function<void(ISocketStream * StreamSock)> actualwork);
	void IncrementWorkerCount(int i = 1);
};
