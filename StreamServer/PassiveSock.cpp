#include "stdafx.h"
#include <process.h>
#include "PassiveSock.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock

CPassiveSock::CPassiveSock(SOCKET s, HANDLE hServerStopEvent)
{
	LastError = 0;
	RecvInitiated = false;
	TimeoutSeconds = 1; // Default timeout is 1 seconds, encourages callers to set it
	ActualSocket = s;
	read_event = WSACreateEvent();  // if create fails we should return an error
	WSAResetEvent(read_event);
	write_event = WSACreateEvent();  // if create fails we should return an error
	WSAResetEvent(write_event);
	int rc = true;
	setsockopt(ActualSocket, IPPROTO_TCP, TCP_NODELAY, (char *)&rc, sizeof(int));
	m_hStopEvent = hServerStopEvent;
}

CPassiveSock::~CPassiveSock()
{
	WSACloseEvent(read_event);
	WSACloseEvent(write_event);
	closesocket(ActualSocket);
}

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock member functions

// Receives up to Len bytes of data and returnds the amount received - or SOCKET_ERROR if it times out
int CPassiveSock::Recv(void * const lpBuf, const int Len)
{
	WSABUF buffer;
	WSAEVENT hEvents[2] = {NULL,NULL};
	DWORD
		bytes_read = 0,
		dwWait = 0, 
		msg_flags = 0;
	int rc;

	// Setup up the events to wait on
	hEvents[1] = read_event;
	hEvents[0] = m_hStopEvent;

	if (RecvInitiated)
	{
		// Special case, the previous read timed out, so we are trying again, maybe it completed in the meantime
		rc = SOCKET_ERROR;
		LastError = WSA_IO_PENDING;
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
		LastError=WSAGetLastError();
	}
	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Read in progress, normal case
	{
		CTimeSpan TimeLeft = RecvEndTime - CTime::GetCurrentTime();
		if (TimeLeft.GetTotalSeconds() <= 0)
			dwWait = WAIT_TIMEOUT;
		else
			dwWait = WaitForMultipleObjects(2, hEvents, false, (DWORD)TimeLeft.GetTotalSeconds()*1000);
		if (dwWait == WAIT_OBJECT_0+1) 
		{
			RecvInitiated = false;
			if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_read, true, &msg_flags) && (bytes_read > 0))
				return bytes_read; // Normal case, we read some bytes, it's all good
			else
			{// A bad thing happened
				int e = WSAGetLastError();
				if (e == 0) // The socket was closed
					return 0;
			}
		}
	}
	else if (!rc) // if rc is zero, the read was completed immediately
	{
		RecvInitiated = false;
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_read, true, &msg_flags) && (bytes_read > 0))
			return bytes_read; // Normal case, we read some bytes, it's all good
	}
	return SOCKET_ERROR;
}


// Receives exactly Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CPassiveSock::ReceiveBytes(void * const lpBuf, const int Len)
{
	int
		bytes_received = 0,
		total_bytes_received = 0; 

	RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,TimeoutSeconds);

	while (total_bytes_received < Len)
	{
		bytes_received = Recv((char*)lpBuf+total_bytes_received, Len-total_bytes_received);
		if (bytes_received == SOCKET_ERROR) 
			return SOCKET_ERROR;
		else if (bytes_received == 0) 
			break; // socket is closed, no data left to receive
		else
		{
			total_bytes_received += bytes_received;
		}
	}; // loop
	return (total_bytes_received);
}

void CPassiveSock::SetTimeoutSeconds(int NewTimeoutSeconds)
{
	if (NewTimeoutSeconds>0)
	{
		TimeoutSeconds = NewTimeoutSeconds;
		SendEndTime = RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,TimeoutSeconds);
	}
}

int CPassiveSock::GetLastError()
{
	return LastError; 
}

BOOL CPassiveSock::ShutDown(int nHow)
{
	return ::shutdown(ActualSocket,nHow);
}

HRESULT CPassiveSock::Disconnect(void)
{
	return ShutDown()?HRESULT_FROM_WIN32(GetLastError()):S_OK;
}

//sends a message, or part of one
int CPassiveSock::Send(const void * const lpBuf, const int Len)
{
	WSAOVERLAPPED os;
	WSABUF buffers[2];
	WSAEVENT hEvents[2] = {NULL,NULL};
	DWORD
		dwWait,
		bytes_sent=0,
		msg_flags = 0;

	// Setup up the events to wait on
	hEvents[1] = write_event;
	hEvents[0] = m_hStopEvent;
	// Setup the buffers array
	buffers[0].buf = (char *)lpBuf;
	buffers[0].len = Len;
	msg_flags = 0;
	dwWait = 0;
	int rc;

	LastError = 0;

	// Create the overlapped I/O event and structures
	memset(&os, 0, sizeof(OVERLAPPED));
	os.hEvent = write_event;
	WSAResetEvent(read_event);
	rc = WSASend(ActualSocket, buffers, 1, &bytes_sent, 0, &os, NULL);
	LastError=WSAGetLastError();
	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Write in progress
	{
		CTimeSpan TimeLeft = SendEndTime - CTime::GetCurrentTime();
		dwWait = WaitForMultipleObjects(2, hEvents, false, (DWORD)TimeLeft.GetTotalSeconds()*1000);
		if (dwWait == WAIT_OBJECT_0+1) // I/O completed
		{	
			if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_sent, true, &msg_flags))
				return bytes_sent;
		}
	}
	else if (!rc) // if rc is zero, the read was completed immediately
	{
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_sent, true, &msg_flags))
			return bytes_sent;
	}
	return SOCKET_ERROR;
}

//sends all the data or returns a timeout
int CPassiveSock::SendBytes(const void * const lpBuf, const int Len)
{
	int
		bytes_sent = 0,
		total_bytes_sent = 0; 

	RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0,0,0,TimeoutSeconds);

	while (total_bytes_sent < Len)
	{
		bytes_sent = Send((char*)lpBuf + total_bytes_sent, Len - total_bytes_sent);
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
