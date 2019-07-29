#pragma once
#include "BaseSock.h"

/////////////////////////////////////////////////////////////////////////////
// CActiveSock


class CActiveSock : private CBaseSock
{
public:
	explicit CActiveSock(HANDLE StopEvent);
	virtual ~CActiveSock();
	bool Connect(LPCTSTR HostName, USHORT PortNumber);
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	int RecvMsg(LPVOID lpBuf, const size_t Len);
	// Sends exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendMsg(LPCVOID lpBuf, const size_t Len);
    // These are actually the ISocketStream methods, but ISocketStream is not explicitly used
	using CBaseSock::RecvPartial;
	using CBaseSock::SendPartial;
	using CBaseSock::GetLastError;
	using CBaseSock::Disconnect;
	using CBaseSock::SetRecvTimeoutSeconds;
	using CBaseSock::GetRecvTimeoutSeconds;
	using CBaseSock::SetSendTimeoutSeconds;
	using CBaseSock::GetSendTimeoutSeconds;
	using CBaseSock::StartRecvTimer;
	using CBaseSock::StartSendTimer;

protected:
	using CBaseSock::ActualSocket;
	using CBaseSock::m_hStopEvent;

private:
};