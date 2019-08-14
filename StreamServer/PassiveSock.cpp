#include "pch.h"
#include "framework.h"
#include "PassiveSock.h"

CPassiveSock::CPassiveSock(SOCKET s, HANDLE StopEvent)
	:CBaseSock(s, StopEvent)
{
}
