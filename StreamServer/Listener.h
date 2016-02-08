#pragma once
#include "StdAfx.h"
#include <functional>
#include <wincrypt.h>

class ISocketStream;

class CListener
{
public:
	enum ErrorType{
		NoError,
		UnknownError,
		SocketInuse,
		SocketUnusable
	};
	CListener();
	~CListener();
private:
	SOCKET m_iListenSockets[FD_SETSIZE];
	HANDLE m_hSocketEvents[FD_SETSIZE];
	int m_iNumListenSockets;
	CCriticalSection m_WorkerThreadLock;
	CWinThread * m_ListenerThread;
	static UINT __cdecl Worker(LPVOID);
	static UINT __cdecl ListenerWorker(LPVOID);
	void Listen(void);
	std::function<void(ISocketStream * StreamSock)> m_actualwork;
public:
	void LogWarning(const WCHAR* const);
	void LogWarning(const CHAR* const);
	int m_WorkerThreadCount;
	CEvent m_StopEvent;
	// Initialize the listener
	ErrorType Initialize(int TCPSocket);
   std::function<SECURITY_STATUS(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)> SelectServerCert;
   std::function<bool(PCCERT_CONTEXT pCertContext, const bool trusted)> ClientCertAcceptable;
   void EndListening(void);
	void BeginListening(std::function<void(ISocketStream * StreamSock)> actualwork);
};

