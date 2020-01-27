#include "pch.h"
#include "framework.h"

#include "Listener.h"
#include "SSLServer.h" 
#include "Utilities.h"

// CListener object, listens for connections on one thread, and initiates a worker
// thread each time a client connects.
CListener::CListener()
{
	for (int i = 0; i < FD_SETSIZE; i++)
	{
		m_iListenSockets[i] = INVALID_SOCKET;
		m_hSocketEvents[i] = nullptr;
	}
}

CListener::~CListener()
{
	for (int i = 0; i < FD_SETSIZE; i++)
	{
		if (m_iListenSockets[i] != INVALID_SOCKET)
			closesocket(m_iListenSockets[i]);
		if (m_hSocketEvents[i])
			CloseHandle(m_hSocketEvents[i]);
	}
}

// This is the individual worker process, all it does is start, change its name to something useful,
// then call the Lambda function passed in via the BeginListening method
void __cdecl CListener::Worker(LPVOID v)
{
	std::unique_ptr<CSSLServer> SSLServer(reinterpret_cast<CSSLServer*>(v));
	SetThreadName("Connection Worker");
	// Invoke the caller provided function defining the work to do, passing an interface which
	// allows the user code to send and receive messages and so on.  
	(SSLServer->GetListener()->m_actualwork)(SSLServer->GetSocketStream());
}

// Worker process for connection listening
void __cdecl CListener::ListenerWorker(LPVOID v)
{
	auto * Listener = static_cast<CListener*>(v); // See _beginthread call for parameter definition

	SetThreadName("Listener");
	Listener->Listen();
}

// Initialize the listener, set up the socket to listen on, or return an error
CListener::ErrorType CListener::Initialize(int TCPSocket)
{
	std::wstring TCPSocketText = string_format(L"%i", TCPSocket);

	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(1, 1), &wsadata))
		return CListener::ErrorType::UnknownError;

	// Get list of addresses to listen on
	ADDRINFOT Hints, *AddrInfo, *AI;
	memset(&Hints, 0, sizeof(Hints));
	Hints.ai_family = PF_UNSPEC;
	Hints.ai_socktype = SOCK_STREAM;
	Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	if (GetAddrInfo(nullptr, TCPSocketText.c_str(), &Hints, &AddrInfo) != 0)
	{
		WCHAR MsgText[100];
		StringCchPrintf(MsgText, _countof(MsgText), L"getaddressinfo error: %i", GetLastError());
		LogWarning(MsgText);
		return CListener::ErrorType::UnknownError;
	}

	// Create one or more passive sockets to listen on
	int i;
	for (i = 0, AI = AddrInfo; AI != nullptr; AI = AI->ai_next)
	{
		// Did we receive more addresses than we can handle?  Highly unlikely, but check anyway.
		if (i == FD_SETSIZE) break;

		// Only support PF_INET and PF_INET6.  If something else, skip to next address.
		if ((AI->ai_family != AF_INET) && (AI->ai_family != AF_INET6)) continue;

		// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit i = %d, ai_family = %d"), i, AI->ai_family;
		// LogWarning(MsgText);

		m_hSocketEvents[i] = CreateEvent(
			nullptr,		// no security attributes
			true,		// manual reset event
			false,		// not signaled
			nullptr);		// no name

		if (!(m_hSocketEvents[i]))
			return CListener::ErrorType::UnknownError;

		// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit Created m_hSocketEvents[%d], handle=%d"), i, m_hSocketEvents[i];
		// LogWarning(MsgText);

		m_iListenSockets[i] = WSASocket(AI->ai_family, SOCK_STREAM, 0, nullptr, 0, WSA_FLAG_OVERLAPPED);
		if (m_iListenSockets[i] == INVALID_SOCKET)
			return CListener::ErrorType::SocketUnusable;

		// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit binding m_iListenSockets[%d] to sa_family=%u sa_data=%s len=%d"), i, AI->ai_addr->sa_family, AI->ai_addr->sa_data, AI->ai_addrlen;
		// LogWarning(MsgText);

		int rc = bind(m_iListenSockets[i], AI->ai_addr, (int)AI->ai_addrlen);
		if (rc)
		{
			if (WSAGetLastError() == WSAEADDRINUSE)
				return CListener::ErrorType::SocketInuse;
			else
				return CListener::ErrorType::SocketUnusable;
		}

		if (listen(m_iListenSockets[i], 10))
			return CListener::ErrorType::SocketUnusable;
		if (WSAEventSelect(m_iListenSockets[i], m_hSocketEvents[i], FD_ACCEPT))
			return CListener::ErrorType::SocketUnusable;
		i++;
	}

	m_iNumListenSockets = i;

	// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit no errors, m_iNumListenSockets = %d"), m_iNumListenSockets;
	// LogWarning(MsgText);

	return CListener::ErrorType::NoError;
}

// Start listening for connections, if a timeout is specified keep listening until then
void CListener::BeginListening(std::function<void(ISocketStream * StreamSock)> actualwork)
{
	m_actualwork = actualwork;
	m_ListenerThread = _beginthread(ListenerWorker, 0, this);
}

void CListener::IncrementWorkerCount(int i)
{
	m_WorkerCountLock.Enter();
	m_WorkerCount += i;
	m_WorkerCountLock.Leave();
}

// Stop listening, tells the listener thread it can stop, then waits for it to terminate
void CListener::EndListening()
{
	m_StopEvent.Set();
	if (m_ListenerThread)
	{
		WaitForSingleObject((HANDLE)m_ListenerThread, INFINITE); // Will auto delete
	}
	m_ListenerThread = 0;
}

// Log a warning
void CListener::LogWarning(const WCHAR* const msg)
{
	DebugMsg(ATL::CW2A(msg));
}
void CListener::LogWarning(const CHAR* const msg)
{
	DebugMsg(msg);
}

// Listen for connections until the "stop" event is caused, this is invoked on
// its own thread
void CListener::Listen()
{
	HANDLE hEvents[FD_SETSIZE + 1];
	SOCKET iReadSocket = NULL;
	//WCHAR MsgText[100];

	m_WorkerCount = 0;

	DebugMsg("Start CListener::Listen method");

	// StringCchPrintf(MsgText, _countof(MsgText), L"CListener::Listen m_iNumListenSockets= %d"), m_iNumListenSockets;
	// LogWarning(MsgText);

	hEvents[0] = m_StopEvent;
	// StringCchPrintf(MsgText, _countof(MsgText), L"CListener::Listen hEvents[0] = m_StopEvent = %d"), m_StopEvent;
	// LogWarning(MsgText);

	// Add the events for each socket type (two at most, one for IPv4, one for IPv6)
	for (int i = 0; i < m_iNumListenSockets; i++)
	{
		hEvents[i + 1] = m_hSocketEvents[i];
		// StringCchPrintf(MsgText, _countof(MsgText), L"CListener::Listen hEvents[%d] = m_hSocketEvents[%d] = %d"), i+1, i, m_hSocketEvents[i];
		// LogWarning(MsgText);
	}

	// Loop until there is a problem or the shutdown event is caused
	while (true)
	{
		// StringCchPrintf(MsgText, _countof(MsgText), L"CListener::Listen entering WaitForMultipleObjects for %d objects"), m_iNumListenSockets+1;
		// LogWarning(MsgText);

    const DWORD dwWait = WaitForMultipleObjects(m_iNumListenSockets + 1, hEvents, false, INFINITE);

		if (dwWait == WAIT_OBJECT_0)
		{
			// LogWarning("CListener::Listen received a stop event");
			break; // Received a stop event
		}
		int iMyIndex = dwWait - 1;
		// StringCchPrintf(MsgText, _countof(MsgText), L"CListener::Listen event %d triggered, iMyIndex = %d"), dwWait, iMyIndex;
		// LogWarning(MsgText);

		WSAResetEvent(m_hSocketEvents[iMyIndex]);
		iReadSocket = accept(m_iListenSockets[iMyIndex], nullptr, nullptr);
		if (iReadSocket == INVALID_SOCKET)
		{
			LogWarning("iReadSocket == INVALID_SOCKET");
			break;
		}

		// A request to open a socket has been received, begin a thread to handle that connection
		DebugMsg("Starting worker");

		auto SSLServer = CSSLServer::Create(iReadSocket, this);
		if (SSLServer && SSLServer->IsConnected)
			_beginthread(Worker, 0, SSLServer);
		else
			delete SSLServer;
		iReadSocket = INVALID_SOCKET;
	}
	// Either we're done, or there has been a problem, wait for all the worker threads to terminate
	Sleep(500);
	m_WorkerCountLock.Enter();
	while (m_WorkerCount)
	{
		m_WorkerCountLock.Leave();
		Sleep(1000);
		DebugMsg("Waiting for all workers to terminate: worker thread count = %i", m_WorkerCount);
		m_WorkerCountLock.Enter();
	};
	m_WorkerCountLock.Leave();
	if ((iReadSocket != NULL) && (iReadSocket != INVALID_SOCKET))
		closesocket(iReadSocket);
	DebugMsg("End Listen method");
}
