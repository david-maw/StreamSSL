#include "pch.h"
#include "framework.h"

#include "Listener.h"

// CListener object, listens for connections on one thread, and initiates a worker
// thread each time a client connects.
CListener::CListener()
	:m_StopEvent(FALSE, TRUE),
	m_TransportCount(0),
	m_ListenerThread(NULL),
	m_iNumListenSockets(0)
{
	for (int i = 0; i < FD_SETSIZE; i++)
	{
		m_iListenSockets[i] = INVALID_SOCKET;
		m_hSocketEvents[i] = NULL;
	}
}

CListener::~CListener()
{
	m_ListenerThread = NULL;
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
UINT __cdecl CListener::Worker(void * v)
{
	CTransport * Transport = reinterpret_cast<CTransport*>(v);
	CListener * Listener = Transport->m_Listener;

	SetThreadName("Connection Worker");
	(Listener->m_actualwork)(Transport->SocketStream);
	delete Transport;
	return 0;
}

// Worker process for connection listening
UINT __cdecl CListener::ListenerWorker(LPVOID v)
{
	CListener * Listener = (CListener *)v; // See _beginthread call for parameter definition

	SetThreadName("Listener");
	Listener->Listen();
	return 0;
}

// Initialize the listener, set up the socket to listen on, or return an error
CListener::ErrorType CListener::Initialize(int TCPSocket)
{
	std::wstring TCPSocketText = string_format(L"%i", TCPSocket);

	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(2, 0), &wsadata))
		return UnknownError;

	// Get list of addresses to listen on
	ADDRINFOT Hints, *AddrInfo, *AI;
	memset(&Hints, 0, sizeof(Hints));
	Hints.ai_family = PF_UNSPEC;
	Hints.ai_socktype = SOCK_STREAM;
	Hints.ai_flags = AI_NUMERICHOST | AI_PASSIVE;
	if (GetAddrInfo(NULL, TCPSocketText.c_str(), &Hints, &AddrInfo) != 0)
	{
		WCHAR MsgText[100];
		StringCchPrintf(MsgText, _countof(MsgText), L"getaddressinfo error: %i", GetLastError());
		LogWarning(MsgText);
		return UnknownError;
	}

	// Create one or more passive sockets to listen on
	int i;
	for (i = 0, AI = AddrInfo; AI != NULL; AI = AI->ai_next)
	{
		// Did we receive more addresses than we can handle?  Highly unlikely, but check anyway.
		if (i == FD_SETSIZE) break;

		// Only support PF_INET and PF_INET6.  If something else, skip to next address.
		if ((AI->ai_family != AF_INET) && (AI->ai_family != AF_INET6)) continue;

		// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit i = %d, ai_family = %d"), i, AI->ai_family;
		// LogWarning(MsgText);

		m_hSocketEvents[i] = CreateEvent(
			NULL,		// no security attributes
			true,		// manual reset event
			false,		// not signaled
			NULL);		// no name

		if (!(m_hSocketEvents[i]))
			return UnknownError;

		// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit Created m_hSocketEvents[%d], handle=%d"), i, m_hSocketEvents[i];
		// LogWarning(MsgText);

		m_iListenSockets[i] = WSASocket(AI->ai_family, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
		if (m_iListenSockets[i] == INVALID_SOCKET)
			return SocketUnusable;

		// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit binding m_iListenSockets[%d] to sa_family=%u sa_data=%s len=%d"), i, AI->ai_addr->sa_family, AI->ai_addr->sa_data, AI->ai_addrlen;
		// LogWarning(MsgText);

		int rc = bind(m_iListenSockets[i], AI->ai_addr, (int)AI->ai_addrlen);
		if (rc)
		{
			if (WSAGetLastError() == WSAEADDRINUSE)
				return SocketInuse;
			else
				return SocketUnusable;
		}

		if (listen(m_iListenSockets[i], 10))
			return SocketUnusable;
		if (WSAEventSelect(m_iListenSockets[i], m_hSocketEvents[i], FD_ACCEPT))
			return SocketUnusable;
		i++;
	}

	m_iNumListenSockets = i;

	// StringCchPrintf(MsgText, _countof(MsgText), L"::OnInit no errors, m_iNumListenSockets = %d"), m_iNumListenSockets;
	// LogWarning(MsgText);

	return NoError;
}

// Start listening for connections, if a timeout is specified keep listening until then
void CListener::BeginListening(std::function<void(ISocketStream * StreamSock)> actualwork)
{
	m_actualwork = actualwork;
	m_ListenerThread = AfxBeginThread(ListenerWorker, this);
}

void CListener::IncrementTransportCount(int i)
{
	m_TransportCountLock.Lock();
	m_TransportCount += i;
	m_TransportCountLock.Unlock();
}

// Stop listening, tells the listener thread it can stop, then waits for it to terminate
void CListener::EndListening()
{
	m_StopEvent.SetEvent();
	if (m_ListenerThread)
	{
		WaitForSingleObject(m_ListenerThread->m_hThread, INFINITE); // Will auto delete
	}
	m_ListenerThread = NULL;
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

	m_TransportCount = 0;

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
		iReadSocket = accept(m_iListenSockets[iMyIndex], 0, 0);
		if (iReadSocket == INVALID_SOCKET)
		{
			LogWarning("iReadSocket == INVALID_SOCKET");
			break;
		}

		// A request to open a socket has been received, begin a thread to handle that connection
		DebugMsg("Starting worker");

		CTransport * Transport = new CTransport(iReadSocket, this); // Deleted by worker thread
		if (Transport->IsConnected)
			AfxBeginThread(Worker, Transport);
		else
			delete Transport;
		iReadSocket = INVALID_SOCKET;
	}
	// Either we're done, or there has been a problem, wait for all the worker threads to terminate
	Sleep(500);
	m_TransportCountLock.Lock();
	while (m_TransportCount)
	{
		m_TransportCountLock.Unlock();
		Sleep(1000);
		DebugMsg("Waiting for all workers to terminate: worker thread count = %i", m_TransportCount);
		m_TransportCountLock.Lock();
	};
	m_TransportCountLock.Unlock();
	if ((iReadSocket != NULL) && (iReadSocket != INVALID_SOCKET))
		closesocket(iReadSocket);
	DebugMsg("End Listen method");
}
