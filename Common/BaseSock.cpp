#include "pch.h"
#include "framework.h"

#include "BaseSock.h"

CBaseSock::CBaseSock(HANDLE StopEvent)
: m_hStopEvent(StopEvent)
{
}

DWORD CBaseSock::GetLastError() const
{
	return LastError;
}

BOOL CBaseSock::ShutDown(int nHow)
{
	return ::shutdown(ActualSocket, nHow);
}