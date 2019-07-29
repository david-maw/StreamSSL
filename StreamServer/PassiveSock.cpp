#include "pch.h"
#include "framework.h"

#include "PassiveSock.h"

#include <process.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock

CPassiveSock::CPassiveSock(SOCKET s, HANDLE hServerStopEvent)
 : CBaseSock(hServerStopEvent)
{
	ActualSocket = s;
	if FAILED(Setup())
		throw("Setup failed");
}

CPassiveSock::~CPassiveSock()
{
}

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock member functions


// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CPassiveSock::RecvPartial(LPVOID lpBuf, const size_t Len)
{
	return CBaseSock::RecvPartial(lpBuf, Len);
}


// Receives exactly Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
int CPassiveSock::ReceiveBytes(void * const lpBuf, const size_t Len)
{
	size_t total_bytes_received = 0;

	StartRecvTimer(); // Allow RecvPartial to start timing

	while (total_bytes_received < Len)
	{
		const size_t bytes_received = RecvPartial((char*)lpBuf + total_bytes_received, Len - total_bytes_received);
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

DWORD CPassiveSock::GetLastError() const
{
	return CBaseSock::GetLastError();
}

HRESULT CPassiveSock::Disconnect()
{
	return ShutDown() ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
}


//sends a message, or part of one
int CPassiveSock::SendPartial(LPCVOID lpBuf, const size_t Len)
{
	return CBaseSock::SendPartial(lpBuf,Len);
}

//sends all the data or returns a timeout
int CPassiveSock::SendBytes(const void * const lpBuf, const size_t Len)
{
	size_t total_bytes_sent = 0;

	SendEndTime = 0; // Allow it to be reset by Send

	while (total_bytes_sent < Len)
	{
		const size_t bytes_sent = SendPartial((char*)lpBuf + total_bytes_sent, Len - total_bytes_sent);
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


void CPassiveSock::SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds)
{
	CBaseSock::SetRecvTimeoutSeconds(NewRecvTimeoutSeconds);
}

int CPassiveSock::GetRecvTimeoutSeconds() const
{
	return CBaseSock::GetRecvTimeoutSeconds();
}

void CPassiveSock::SetSendTimeoutSeconds(int NewSendTimeoutSeconds)
{
	CBaseSock::SetSendTimeoutSeconds(NewSendTimeoutSeconds);
}

int CPassiveSock::GetSendTimeoutSeconds() const
{
	return CBaseSock::GetSendTimeoutSeconds();
}

void CPassiveSock::StartRecvTimer()
{
	CBaseSock::StartRecvTimer();
}

void CPassiveSock::StartSendTimer()
{
	CBaseSock::StartSendTimer();
}