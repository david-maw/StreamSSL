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

int CPassiveSock::RecvPartial(LPVOID lpBuf, const size_t Len)
{
	return CBaseSock::RecvPartial(lpBuf, Len);
}

DWORD CPassiveSock::GetLastError() const
{
	return CBaseSock::GetLastError();
}

int CPassiveSock::SendMsg(LPCVOID lpBuf, const size_t Len)
{
	return CBaseSock::SendMsg(lpBuf, Len);
}

int CPassiveSock::RecvMsg(LPVOID lpBuf, const size_t Len)
{
	return CBaseSock::RecvMsg(lpBuf, Len);
}

HRESULT CPassiveSock::Disconnect()
{
	return ShutDown() ? HRESULT_FROM_WIN32(GetLastError()) : S_OK;
}

int CPassiveSock::SendPartial(LPCVOID lpBuf, const size_t Len)
{
	return CBaseSock::SendPartial(lpBuf,Len);
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