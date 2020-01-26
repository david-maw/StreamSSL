#include "pch.h"
#include "framework.h"

#include "BaseSock.h"
#include "Utilities.h"

CBaseSock::CBaseSock(SOCKET s, HANDLE StopEvent)
	: CBaseSock(StopEvent)
{
	ActualSocket = s;
	if FAILED(Setup())
		throw("Setup failed");
}


CBaseSock::CBaseSock(HANDLE StopEvent)
: m_hStopEvent(StopEvent)
{
	//
	// Initialize the WinSock subsystem.
	//
	WSADATA wsadata;
	if (WSAStartup(MAKEWORD(1, 1), &wsadata) == SOCKET_ERROR)
	{
		DebugMsg("Error %d returned by WSAStartup", GetLastError());
		throw "WSAStartup error";
	}
}

CBaseSock::~CBaseSock()
{
	Disconnect();
	WSACleanup();
}

DWORD CBaseSock::GetLastError() const
{
	return LastError;
}

HRESULT CBaseSock::Setup()
{
	int rc = 1;
	setsockopt(ActualSocket, IPPROTO_TCP, TCP_NODELAY, (char*)& rc, sizeof(int));
	if (!read_event)
		read_event = WSACreateEvent();
	if (read_event != WSA_INVALID_EVENT)
	{
		if (!write_event)
			write_event = WSACreateEvent();
		if (write_event != WSA_INVALID_EVENT)
		{
			if (WSAResetEvent(read_event) && WSAResetEvent(write_event))
				DebugMsg("CBaseSock::Initialize - Events initialized");
		}
	}

	LastError = WSAGetLastError();
	return HRESULT_FROM_WIN32(LastError);
}

HRESULT CBaseSock::Disconnect(bool CloseUnderlyingConnection)
{
	LastError = ERROR_SUCCESS;

	if (ActualSocket == INVALID_SOCKET || !CloseUnderlyingConnection)
		return S_OK;
	else if (WSACloseEvent(read_event) && WSACloseEvent(write_event) && CloseAndInvalidateSocket())
		DebugMsg("Disconnect succeeded");
	else
	{
		LastError = ::WSAGetLastError();
		DebugMsg("Disconnect failed, WSAGetLastError returned 0x%.8x", LastError);
	}
	return HRESULT_FROM_WIN32(LastError);
}

bool CBaseSock::CloseAndInvalidateSocket()
{
	const auto nRet = closesocket(ActualSocket);
	ActualSocket = INVALID_SOCKET;
	return nRet == 0;
}

// The general model of timer logic is this - if you want to control the timer, call StartxxxTimer and it will
// be started immediately and used when RecvPartial or SendPartial is called.  It times whole messages, not the fragments TCP/IP
// may deliver. So receiving an SSL message should happen within <timeout> seconds, whether it arrives in one 
// piece or many.
//
// Setting the send or recv timeout generally switches back to automated operation (meaning Send and Recv start
// the relevant timer whenever they are called) but there's an extra parameter to SetxxxTimoutSeconds so you can 
// specify manual behaviour explicitly if you wish.

void CBaseSock::StartRecvTimerInternal()
{
	RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, RecvTimeoutSeconds);
}

void CBaseSock::StartSendTimerInternal()
{
	SendEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, SendTimeoutSeconds);
}

void CBaseSock::StartRecvTimer()
{
	RecvTimerAutomatic = false; // It will be set manually (by calling this method) from now on
	StartRecvTimerInternal();
}

void CBaseSock::StartSendTimer()
{
	SendTimerAutomatic = false; // It will be set manually (by callong this method) from now on
	StartSendTimerInternal();
}

void CBaseSock::SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds, bool NewTimerAutomatic)
{
	if (NewRecvTimeoutSeconds == INFINITE)
		NewRecvTimeoutSeconds = MAXINT;
	if (NewRecvTimeoutSeconds > 0)
	{
		RecvTimeoutSeconds = NewRecvTimeoutSeconds;
		// RecvEndTime is untouched because a receive may be in process
	}
	RecvTimerAutomatic = NewTimerAutomatic;
}

int CBaseSock::GetRecvTimeoutSeconds() const
{
	return RecvTimeoutSeconds;
}

void CBaseSock::SetSendTimeoutSeconds(int NewSendTimeoutSeconds, bool NewTimerAutomatic)
{
	if (NewSendTimeoutSeconds == INFINITE)
		NewSendTimeoutSeconds = MAXINT;
	if (NewSendTimeoutSeconds > 0)
	{
		SendTimeoutSeconds = NewSendTimeoutSeconds;
		// SendEndTime is untouched, because a Send may be in process
	}
	SendTimerAutomatic = NewTimerAutomatic;
}

int CBaseSock::GetSendTimeoutSeconds() const
{
	return SendTimeoutSeconds;
}

// Receives no more than Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out before receiving MinLen
int CBaseSock::Recv(LPVOID lpBuf, const size_t Len, const size_t MinLen)
{
	if (RecvTimerAutomatic)
		StartRecvTimerInternal();
	size_t total_bytes_received = 0;
	while (total_bytes_received < MinLen)
	{
		const size_t bytes_received = RecvPartial((char*)lpBuf + total_bytes_received, Len - total_bytes_received);
		if (bytes_received == SOCKET_ERROR)
			return SOCKET_ERROR;
		else if (bytes_received == 0)
			break; // socket is closed, no data left to receive
		else
			total_bytes_received += bytes_received;
	}; // loop
	return (static_cast<int>(total_bytes_received));
}

// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CBaseSock::RecvPartial(LPVOID lpBuf, const size_t Len)
{
	DWORD bytes_read = 0;
	DWORD msg_flags = 0;
	int rc = 0;

	// Setup up the events to wait on
	WSAEVENT hEvents[2] = { m_hStopEvent, read_event };

	const CTimeSpan TimeLeft = RecvEndTime - CTime::GetCurrentTime();
	const auto SecondsLeft = TimeLeft.GetTotalSeconds();
	if (SecondsLeft <= 0)
	{
		LastError = ERROR_TIMEOUT;
		return SOCKET_ERROR;
	}

	if (RecvInitiated)
	{
		// Special case, the previous read was left active so we are trying again, maybe it completed in the meantime
		rc = SOCKET_ERROR;
		LastError = WSA_IO_PENDING;
	}
	else
	{
		// Normal case, the last read completed, so we need to initiate another

		// Create the overlapped I/O event and structures
		memset(&os, 0, sizeof(OVERLAPPED));
		ZeroMemory(&os, sizeof(os));
		os.hEvent = hEvents[1];
		if (!WSAResetEvent(os.hEvent))
		{
			LastError = WSAGetLastError();
			return SOCKET_ERROR;
		}
		RecvInitiated = true;
		// Setup the buffers array
		WSABUF buffer{ static_cast<ULONG>(Len), static_cast<char*>(lpBuf) };
		rc = WSARecv(ActualSocket, &buffer, 1, &bytes_read, &msg_flags, &os, nullptr); // Start an asynchronous read
		LastError = WSAGetLastError();
	}

	bool IOCompleted = !rc; // if rc is zero, the read was completed immediately

	// Now wait for the I/O to complete if necessary, and see what happened

	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Read in progress, normal case
	{
		const DWORD dwWait = WaitForMultipleObjects(2, hEvents, false, static_cast<DWORD>(SecondsLeft) * 1000);
		switch (dwWait)
		{
		case WAIT_OBJECT_0 + 1: // The read event 
			IOCompleted = true;
			LastError = 0;
			break;
		case WAIT_ABANDONED_0:
		case WAIT_ABANDONED_0 + 1:
			break;
		case WAIT_TIMEOUT:
			LastError = ERROR_TIMEOUT;
			break;
		case WAIT_FAILED:
			LastError = ::GetLastError();
			break;
		default:
			break;
		}
	}

	if (IOCompleted)
	{
		RecvInitiated = false;
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_read, true, &msg_flags) && (bytes_read > 0))
		{
			return bytes_read; // Normal case, we read some bytes, it's all good
		}
		else
		{	// A bad thing happened
			const int e = WSAGetLastError();
			if (e == 0) // The socket was closed
				return 0;
			else if (LastError == 0)
				LastError = e;
		}
	}
	return SOCKET_ERROR;
}

//sends all the data requested or returns a timeout
int CBaseSock::Send(LPCVOID lpBuf, const size_t Len)
{
	if (SendTimerAutomatic)
		StartSendTimerInternal();
	ULONG total_bytes_sent = 0;
	while (total_bytes_sent < Len)
	{
		const ULONG bytes_sent = SendPartial((char*)lpBuf + total_bytes_sent, Len - total_bytes_sent);
		if ((bytes_sent == SOCKET_ERROR))
			return SOCKET_ERROR;
		else if (bytes_sent == 0)
			if (total_bytes_sent == 0)
				return SOCKET_ERROR;
			else
				break; // socket is closed, no chance of sending more
		else
			total_bytes_sent += bytes_sent;
	}; // loop
	return (total_bytes_sent);
}

//sends a message, or part of one
int CBaseSock::SendPartial(LPCVOID lpBuf, const size_t Len)
{
	DebugMsg("CBaseSock::SendPartial, Len = %d", Len);

	DWORD bytes_sent = 0;

	// Setup up the events to wait on
	WSAEVENT hEvents[2] = { m_hStopEvent, write_event };

	// Create the overlapped I/O event and structures
	memset(&os, 0, sizeof(OVERLAPPED));
	os.hEvent = hEvents[1];
	if (!WSAResetEvent(os.hEvent))
	{
		LastError = WSAGetLastError();
		return SOCKET_ERROR;
	}

	// Setup the buffer array
	WSABUF buffer{ static_cast<ULONG>(Len), static_cast<char*>(const_cast<void*>(lpBuf)) };

	const int rc = WSASend(ActualSocket, &buffer, 1, &bytes_sent, 0, &os, nullptr);
	LastError = WSAGetLastError();

	const CTimeSpan TimeLeft = SendEndTime - CTime::GetCurrentTime();
	const auto SecondsLeft = TimeLeft.GetTotalSeconds();
	if (SecondsLeft <= 0)
	{
		LastError = ERROR_TIMEOUT;
		return SOCKET_ERROR;
	}

	bool IOCompleted = !rc; // if rc is zero, the write was completed immediately, which is common

	// Now wait for the I/O to complete if necessary, and see what happened

	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Write in progress
	{
		const DWORD dwWait = WaitForMultipleObjects(2, hEvents, false, static_cast<DWORD>(SecondsLeft) * 1000);
		switch (dwWait)
		{
		case WAIT_OBJECT_0 + 1: // The write event
			IOCompleted = true;
			LastError = 0;
			break;
		case WAIT_ABANDONED_0:
		case WAIT_ABANDONED_0 + 1:
			break;
		case WAIT_TIMEOUT:
			LastError = ERROR_TIMEOUT;
			break;
		case WAIT_FAILED:
			LastError = ::GetLastError();
			break;
		default:
			break;
		}
	}

	if (IOCompleted)
	{
		DWORD msg_flags = 0;
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_sent, true, &msg_flags))
		{
			return bytes_sent;
		}
		else
		{	// A bad thing happened
			const int e = WSAGetLastError();
			if (e == 0) // The socket was closed
				return 0;
			else if (LastError == 0)
				LastError = e;
		}
	}
	return SOCKET_ERROR;
}

bool CBaseSock::Connect(LPCWSTR HostName, USHORT PortNumber)
{
	int iResult;
	BOOL bSuccess;
	SOCKADDR_STORAGE LocalAddr = { 0 };
	SOCKADDR_STORAGE RemoteAddr = { 0 };
	DWORD dwLocalAddr = sizeof(LocalAddr);
	DWORD dwRemoteAddr = sizeof(RemoteAddr);
	WCHAR PortName[10] = { 0 };
	timeval Timeout = { 0 };

	Timeout.tv_sec = GetSendTimeoutSeconds();

	_itow_s(PortNumber, PortName, _countof(PortName), 10);

	ActualSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (ActualSocket == INVALID_SOCKET) {
		DebugMsg("socket failed with error: %d\n", WSAGetLastError());
		return false;
	}

	// Note that WSAConnectByName requires Vista or Server 2008
	bSuccess = WSAConnectByName(ActualSocket, const_cast<LPWSTR>(HostName),
		PortName, &dwLocalAddr,
		(SOCKADDR*)& LocalAddr,
		&dwRemoteAddr,
		(SOCKADDR*)& RemoteAddr,
		&Timeout,
		nullptr);

	if (!bSuccess) {
		LastError = WSAGetLastError();
		DebugMsg("**** WsaConnectByName Error %d connecting to \"%S\" (%S)",
			LastError,
			HostName,
			PortName);
		CloseAndInvalidateSocket();
		return false;
	}
	iResult = setsockopt(ActualSocket, SOL_SOCKET,
		0x7010 /*SO_UPDATE_CONNECT_CONTEXT*/, nullptr, 0);
	if (iResult == SOCKET_ERROR) {
		LastError = WSAGetLastError();
		DebugMsg("setsockopt for SO_UPDATE_CONNECT_CONTEXT failed with error: %d", LastError);
		CloseAndInvalidateSocket();
		return false;
	}
	//// At this point we have a connection, so set up keepalives so we can detect if the host disconnects
	//// This code is commented out because it does not seen to be helpful
	//BOOL so_keepalive = TRUE;
	//int iResult = setsockopt(ActualSocket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&so_keepalive, sizeof(so_keepalive));
	//	if (iResult == SOCKET_ERROR){
	//		LastError = WSAGetLastError();
	//		wprintf(L"setsockopt for SO_KEEPALIVE failed with error: %d\n",
	//			LastError);
	//		CloseAndInvalidateSocket();
	//		return false;
	//	}

	//// Now set keepalive timings

	//DWORD dwBytes = 0;
	//tcp_keepalive sKA_Settings = {0}, sReturned = {0} ;

	//sKA_Settings.onoff = 1 ;
	//sKA_Settings.keepalivetime = 1000; // Keep Alive in 1 sec.
	//sKA_Settings.keepaliveinterval = 1000 ; // Resend if No-Reply
	//if (WSAIoctl(ActualSocket, SIO_KEEPALIVE_VALS, &sKA_Settings,
	//	sizeof(sKA_Settings), &sReturned, sizeof(sReturned), &dwBytes,
	//	NULL, NULL) != 0)
	//{
	//	LastError = WSAGetLastError() ;
	//	wprintf(L"WSAIoctl to set keepalive failed with error: %d\n", LastError);
	//	CloseAndInvalidateSocket();
	//	return false;
	//}

	return SUCCEEDED(Setup());
}
