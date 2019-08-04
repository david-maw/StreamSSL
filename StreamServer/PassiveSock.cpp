#include "pch.h"
#include "framework.h"
#include "PassiveSock.h"

CPassiveSock::CPassiveSock(SOCKET s, HANDLE StopEvent)
	:CBaseSock(s, StopEvent)
{
}

HRESULT CPassiveSock::Disconnect()
{
	return ShutDown() ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
}