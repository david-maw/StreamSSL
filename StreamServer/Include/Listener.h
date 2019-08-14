#pragma once
#include <wincrypt.h>
#include <functional>

class ISocketStream;

class CListener
{
public:
	enum ErrorType {
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
	CWinThread * m_ListenerThread{ nullptr };
	static UINT __cdecl Worker(LPVOID);
	static UINT __cdecl ListenerWorker(LPVOID);
	void Listen();
	std::function<void(ISocketStream * StreamSock)> m_actualwork;
public:
	static void LogWarning(const WCHAR* const);
	static void LogWarning(const CHAR* const);
	int m_WorkerCount{ 0 };
	CEvent m_StopEvent{ FALSE, TRUE };
	// Initialize the listener
	ErrorType Initialize(int TCPSocket);
	std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)> SelectServerCert;
	std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> ClientCertAcceptable;
	void EndListening();
	void BeginListening(std::function<void(ISocketStream * StreamSock)> actualwork);
	void IncrementWorkerCount(int i = 1);
};
