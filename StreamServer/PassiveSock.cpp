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
	ActualSocket = s;
	ZeroMemory(&os, sizeof(os));
	read_event = WSACreateEvent();  // if create fails we should return an error
	WSAResetEvent(read_event);
	write_event = WSACreateEvent();  // if create fails we should return an error
	WSAResetEvent(write_event);
	int rc = 1;
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


void CPassiveSock::ArmRecvTimer()
{
	RecvEndTime = 0; // Allow it to be set next time RecvPartial is called
}

// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CPassiveSock::RecvPartial(void * const lpBuf, const size_t Len)
{
	WSABUF buffer;
	WSAEVENT hEvents[2] = { NULL,NULL };
	DWORD
		bytes_read = 0,
		dwWait = 0,
		msg_flags = 0;
	int rc;

	// Setup up the events to wait on
	hEvents[1] = read_event;
	hEvents[0] = m_hStopEvent;

	if (RecvEndTime == 0)
		RecvEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, TimeoutSeconds);

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
		buffer.len = static_cast<decltype(buffer.len)>(Len);

		// Create the overlapped I/O event and structures
		memset(&os, 0, sizeof(OVERLAPPED));
		os.hEvent = hEvents[1];
		WSAResetEvent(os.hEvent);
		RecvInitiated = true;
		rc = WSARecv(ActualSocket, &buffer, 1, &bytes_read, &msg_flags, &os, NULL); // Start an asynchronous read
		LastError = WSAGetLastError();
	}
	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Read in progress, normal case
	{
		CTimeSpan TimeLeft = RecvEndTime - CTime::GetCurrentTime();
		if (TimeLeft.GetTotalSeconds() <= 0)
			dwWait = WAIT_TIMEOUT;
		else
			dwWait = WaitForMultipleObjects(2, hEvents, false, (DWORD)TimeLeft.GetTotalSeconds() * 1000);
		if (dwWait == WAIT_OBJECT_0 + 1)
		{
			RecvInitiated = false;
			if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_read, true, &msg_flags) && (bytes_read > 0))
				return bytes_read; // Normal case, we read some bytes, it's all good
			else
			{// A bad thing happened, either WSAGetOverlappedResult failed or bytes_read returned zero
				LastError = ERROR_OPERATION_ABORTED;  // One case that gets you here is if the other end disconnects
			}
		}
		else
		{
			LastError = ERROR_TIMEOUT;
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
int CPassiveSock::ReceiveBytes(void * const lpBuf, const size_t Len)
{
	size_t
		bytes_received = 0,
		total_bytes_received = 0;

	ArmRecvTimer(); // Allow RecvPartial to start timing

	while (total_bytes_received < Len)
	{
		bytes_received = RecvPartial((char*)lpBuf + total_bytes_received, Len - total_bytes_received);
		if (bytes_received == SOCKET_ERROR)
			return SOCKET_ERROR;
		else if (bytes_received == 0)
			break; // socket is closed, no data left to receive
		else
		{
			total_bytes_received += bytes_received;
		}
	}; // loop
	return (static_cast<int>(total_bytes_received));
}

void CPassiveSock::SetTimeoutSeconds(int NewTimeoutSeconds)
{
	if (NewTimeoutSeconds > 0)
	{
		TimeoutSeconds = NewTimeoutSeconds;
		// SendEndTime and RecvEndTime are untouched, because a Send or receive may be in process
	}
}

int CPassiveSock::GetLastError()
{
	return LastError;
}

BOOL CPassiveSock::ShutDown(int nHow)
{
	return ::shutdown(ActualSocket, nHow);
}

HRESULT CPassiveSock::Disconnect()
{
	return ShutDown() ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
}

void CPassiveSock::ArmSendTimer()
{
	SendEndTime = 0; // Allow it to be set next time SendPartial is called
}


//sends a message, or part of one
int CPassiveSock::SendPartial(const void * const lpBuf, const size_t Len)
{
	WSABUF buffers[2];
	WSAEVENT hEvents[2] = { NULL,NULL };
	DWORD
		dwWait,
		bytes_sent = 0,
		msg_flags = 0;

	// Setup up the events to wait on
	hEvents[1] = write_event;
	hEvents[0] = m_hStopEvent;
	// Setup the buffers array
	buffers[0].buf = (char *)lpBuf;
	buffers[0].len = static_cast<decltype(buffers[0].len)>(Len);
	msg_flags = 0;
	dwWait = 0;
	int rc;

	LastError = 0;
	if (SendEndTime == 0)
		SendEndTime = CTime::GetCurrentTime() + CTimeSpan(0, 0, 0, TimeoutSeconds);

	// Create the overlapped I/O event and structures
	memset(&os, 0, sizeof(OVERLAPPED));
	os.hEvent = hEvents[1];
	WSAResetEvent(hEvents[1]);
	rc = WSASend(ActualSocket, buffers, 1, &bytes_sent, 0, &os, NULL);
	LastError = WSAGetLastError();
	if ((rc == SOCKET_ERROR) && (LastError == WSA_IO_PENDING))  // Write in progress
	{
		CTimeSpan TimeLeft = SendEndTime - CTime::GetCurrentTime();
		if (TimeLeft.GetTotalSeconds() <= 0)
			dwWait = WAIT_TIMEOUT;
		else
			dwWait = WaitForMultipleObjects(2, hEvents, false, (DWORD)TimeLeft.GetTotalSeconds() * 1000);
		if (dwWait == WAIT_OBJECT_0 + 1) // I/O completed
		{
			if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_sent, true, &msg_flags))
				return bytes_sent;
		}
		else
		{
			LastError = ERROR_TIMEOUT;
		}
	}
	else if (!rc) // if rc is zero, the send was completed immediately
	{
		if (WSAGetOverlappedResult(ActualSocket, &os, &bytes_sent, true, &msg_flags))
			return bytes_sent;
	}
	return SOCKET_ERROR;
}

//sends all the data or returns a timeout
int CPassiveSock::SendBytes(const void * const lpBuf, const size_t Len)
{
	size_t
		bytes_sent = 0,
		total_bytes_sent = 0;

	SendEndTime = 0; // Allow it to be reset by Send

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
	return (static_cast<int>(total_bytes_sent));
}
