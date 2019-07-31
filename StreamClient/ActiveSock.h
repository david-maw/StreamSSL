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
	using CBaseSock::RecvMsg;
	using CBaseSock::SendMsg;
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
};