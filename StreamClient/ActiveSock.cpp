#include "pch.h"
#include "framework.h"
#include "ActiveSock.h"

CActiveSock::CActiveSock(HANDLE StopEvent)
  : CBaseSock(StopEvent)
{
}
