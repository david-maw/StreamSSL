#pragma once
#include "BaseSock.h"
// #include "ISocketStream.h" not needed

/////////////////////////////////////////////////////////////////////////////
// CActiveSock


class CActiveSock : private CBaseSock //, public ISocketStream not needed
{
public:
	explicit CActiveSock(HANDLE StopEvent);
	virtual ~CActiveSock();
	bool Connect(LPCTSTR HostName, USHORT PortNumber);
	using CBaseSock::SetRecvTimeoutSeconds;
	using CBaseSock::GetRecvTimeoutSeconds;
	using CBaseSock::SetSendTimeoutSeconds;
	using CBaseSock::GetSendTimeoutSeconds;
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	int RecvMsg(LPVOID lpBuf, const size_t Len);
	// Sends exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendMsg(LPCVOID lpBuf, const size_t Len);
	using CBaseSock::GetLastError;
	using CBaseSock::RecvPartial;
	using CBaseSock::SendPartial;
	using CBaseSock::Disconnect;

protected:
	using CBaseSock::ActualSocket;
	using CBaseSock::m_hStopEvent;

private:
};