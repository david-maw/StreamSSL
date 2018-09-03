#include <process.h>
#include <stdlib.h>
#include <WS2tcpip.h>
#include <MSTcpIP.h>
#include "Utilities.h"
#include "ActiveSock.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CActiveSock

WSADATA CActiveSock::WsaData;

CActiveSock::CActiveSock(HANDLE StopEvent)
{
	m_hStopEvent = StopEvent;
	//
	// Initialize the WinSock subsystem.
	//

	if (WSAStartup(0x0101, &WsaData) == SOCKET_ERROR)
	{
		DebugMsg("Error %d returned by WSAStartup", GetLastError());
		throw "WSAStartup error";
	}
	LastError = 0;
	RecvInitiated = false;
	RecvTimeoutSeconds = 1; // Default timeout is 1 seconds, encourages callers to set it
	SendTimeoutSeconds = 1; // Default timeout is 1 seconds, encourages callers to set it
	read_event = WSACreateEvent();  // if create fails we should return an error
	WSAResetEvent(read_event);
	write_event = WSACreateEvent();  // if create fails we should return an error
	WSAResetEvent(write_event);
	int rc = true;
	setsockopt(ActualSocket, IPPROTO_TCP, TCP_NODELAY, (char *)&rc, sizeof(int));
}

CActiveSock::~CActiveSock()
{
	WSACloseEvent(read_event);
	WSACloseEvent(write_event);
	WSACleanup();
	closesocket(ActualSocket);
}

/////////////////////////////////////////////////////////////////////////////
// CActiveSock member functions


bool CActiveSock::Connect(LPCTSTR HostName, USHORT PortNumber)
{
	int iResult;
	BOOL bSuccess;
	SOCKADDR_STORAGE LocalAddr = { 0 };
	SOCKADDR_STORAGE RemoteAddr = { 0 };
	DWORD dwLocalAddr = sizeof(LocalAddr);
	DWORD dwRemoteAddr = sizeof(RemoteAddr);
	TCHAR PortName[10] = { 0 };
	timeval Timeout = { 0 };

	Timeout.tv_sec = GetSendTimeoutSeconds();

	_itot_s(PortNumber, PortName, _countof(PortName), 10);

	ActualSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (ActualSocket == INVALID_SOCKET) {
		wprintf(L"socket failed with error: %d\n", WSAGetLastError());
		return false;
	}
	CTime Now = CTime::GetCurrentTime();

	// Note that WSAConnectByName requires Vista or Server 2008
	bSuccess = WSAConnectByName(ActualSocket, const_cast<LPTSTR>(HostName),
		PortName, &dwLocalAddr,
		(SOCKADDR*)&LocalAddr,
		&dwRemoteAddr,
		(SOCKADDR*)&RemoteAddr,
		&Timeout,
		NULL);

	CTimeSpan HowLong = CTime::GetCurrentTime() - Now;

	if (!bSuccess) {
		LastError = WSAGetLastError();
		DebugMsg("**** WsaConnectByName Error %d connecting to \"%S\" (%S)",
			LastError,
			HostName,
			PortName);
		closesocket(ActualSocket);
		return false;
	}
	iResult = setsockopt(ActualSocket, SOL_SOCKET,
		0x7010 /*SO_UPDATE_CONNECT_CONTEXT*/, NULL, 0);
	if (iResult == SOCKET_ERROR) {
		LastError = WSAGetLastError();
		DebugMsg("setsockopt for SO_UPDATE_CONNECT_CONTEXT failed with error: %d", LastError);
		closesocket(ActualSocket);
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
	//		closesocket(ActualSocket);
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
	//	closesocket(ActualSocket);
	//	return false;       
	//}

	return true;
}

// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CActiveSock::RecvPartial(LPVOID lpBuf, const ULONG Len)
{
	WSABUF buffer;
	WSAEVENT hEvents[2] = { read_event, m_hStopEvent };
	DWORD
		bytes_read = 0,
		msg_flags = 0;
	int rc;

	if (RecvInitiated)
	{
		// Special case, the previous read timed out, so we are trying again, maybe it completed in the meantime
		rc = SOCKET_ERROR;
		LastError = WSA_IO_PENDING;
		RecvEndTime = 0;
	}
	else
	{
		// Normal case, the last read completed normally, now we're reading again

		// Setup the buffers array
		buffer.buf = static_cast<char*>(lpBuf);
		buffer.len = Len;

		// Create the overlapped I/O event and structures
		memset(&os, 0, sizeof(OVERLAPPED));
		os.hEvent = hEvents[1];
		WSAResetEvent(os.hEvent);
		RecvInitiated = true;
		rc = WSARecv(ActualSocket, &buffer, 1, &bytes_read, &msg_flags, &os, NULL); // Start an asynchronous read
		LastError = WSAGetLastError();
	}

	// If the timer has been invalidated, restart it
	if (RecvEndTime == 0)
		RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, RecvTimeoutSeconds);

	// Now wait for the I/O to complete if necessary, and see what happened
	bool IOCompleted = false;

	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Read in progress, normal case
	{
		CTimeSpan TimeLeft = RecvEndTime - CTime::GetCurrentTime();
		DWORD dwWait, SecondsLeft = (DWORD)TimeLeft.GetTotalSeconds();
		if (SecondsLeft <= 0)
			dwWait = WAIT_TIMEOUT;
		else
		{
			dwWait = WaitForMultipleObjects(2, hEvents, false, SecondsLeft * 1000);
			if (dwWait == WAIT_OBJECT_0 + 1) // The read event 
				IOCompleted = true;
		}
	}
	else if (!rc) // if rc is zero, the read was completed immediately
		IOCompleted = true;

	if (IOCompleted)
	{
		RecvInitiated = false;
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_read, true, &msg_flags) && (bytes_read > 0))
		{
			LastError = 0;
			if (bytes_read == Len) // We got what was requested
				RecvEndTime = 0; // Restart the timer on the next read
			return bytes_read; // Normal case, we read some bytes, it's all good
		}
		else
		{	// A bad thing happened
			int e = WSAGetLastError();
			if (e == 0) // The socket was closed
				return 0;
			else if (LastError == 0)
				LastError = e;
		}
	}
	return SOCKET_ERROR;
}

// Receives exactly Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CActiveSock::RecvMsg(LPVOID lpBuf, const ULONG Len)
{
	ULONG
		bytes_received = 0,
		total_bytes_received = 0;

	RecvEndTime = 0; // Tell RecvPartial to restart the timer

	while (total_bytes_received < Len)
	{
		bytes_received = RecvPartial((char*)lpBuf + total_bytes_received, Len - total_bytes_received);
		if (bytes_received == SOCKET_ERROR)
			return SOCKET_ERROR;
		else if (bytes_received == 0)
			break; // socket is closed, no data left to receive
		else
			total_bytes_received += bytes_received;
	}; // loop
	return (total_bytes_received);
}

void CActiveSock::SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds)
{
	if (NewRecvTimeoutSeconds == INFINITE)
		NewRecvTimeoutSeconds = MAXINT;
	if (NewRecvTimeoutSeconds > 0)
	{
		RecvTimeoutSeconds = NewRecvTimeoutSeconds;
		RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, RecvTimeoutSeconds);
	}
}

int CActiveSock::GetRecvTimeoutSeconds()
{
	return RecvTimeoutSeconds;
}

void CActiveSock::SetSendTimeoutSeconds(int NewSendTimeoutSeconds)
{
	if (NewSendTimeoutSeconds == INFINITE)
		NewSendTimeoutSeconds = MAXINT;
	if (NewSendTimeoutSeconds > 0)
	{
		SendTimeoutSeconds = NewSendTimeoutSeconds;
		SendEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, SendTimeoutSeconds);
	}
}

int CActiveSock::GetSendTimeoutSeconds()
{
	return SendTimeoutSeconds;
}

DWORD CActiveSock::GetLastError()
{
	return LastError;
}

BOOL CActiveSock::ShutDown(int nHow)
{
	return ::shutdown(ActualSocket, nHow);
}

bool CActiveSock::Close(void)
{
	if (ShutDown() == FALSE)
		return true;
	else
	{
		LastError = ::WSAGetLastError();
		return false;
	}
}

//sends a message, or part of one
int CActiveSock::SendPartial(LPCVOID lpBuf, const ULONG Len)
{
	WSAOVERLAPPED os;
	WSABUF buffer;
	DWORD bytes_sent = 0;

	// Setup the buffer array
	buffer.buf = (char *)lpBuf;
	buffer.len = Len;

	// Reset the timer if it has been invalidated 
	if (SendEndTime == 0)
		SendEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, SendTimeoutSeconds);

	LastError = 0;

	// Create the overlapped I/O event and structures
	memset(&os, 0, sizeof(OVERLAPPED));
	os.hEvent = write_event;
	WSAResetEvent(read_event);
	int rc = WSASend(ActualSocket, &buffer, 1, &bytes_sent, 0, &os, NULL);
	LastError = WSAGetLastError();

	// Now wait for the I/O to complete if necessary, and see what happened
	bool IOCompleted = false;

	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Write in progress
	{
		WSAEVENT hEvents[2] = { write_event, m_hStopEvent };
		DWORD dwWait;
		CTimeSpan TimeLeft = SendEndTime - CTime::GetCurrentTime();
		dwWait = WaitForMultipleObjects(2, hEvents, false, (DWORD)TimeLeft.GetTotalSeconds() * 1000);
		if (dwWait == WAIT_OBJECT_0 + 1) // The write event
			IOCompleted = true;
	}
	else if (!rc) // if rc is zero, the write was completed immediately, which is common
		IOCompleted = true;

	if (IOCompleted)
	{
		DWORD msg_flags = 0;
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_sent, true, &msg_flags))
		{
			if (bytes_sent == Len) // Everything that was requested was sent
				SendEndTime = 0;  // Invalidate the timer so it is set next time through
			return bytes_sent;
		}
	}
	return SOCKET_ERROR;
}

//sends all the data or returns a timeout
int CActiveSock::SendMsg(LPCVOID lpBuf, const ULONG Len)
{
	ULONG
		bytes_sent = 0,
		total_bytes_sent = 0;

	SendEndTime = 0; // Invalidate the timer so SendPartial can reset it.

	while (total_bytes_sent < Len)
	{
		bytes_sent = SendPartial((char*)lpBuf + total_bytes_sent, Len - total_bytes_sent);
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
