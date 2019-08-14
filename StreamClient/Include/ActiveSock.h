#pragma once
#include "BaseSock.h"

class CActiveSock : public CBaseSock
{
public:
	// Active socket which will use "Connect" to a specified destination
	explicit CActiveSock(HANDLE StopEvent);
	// Do not allow passive socket binding to an existing socket
	CActiveSock(SOCKET s, HANDLE StopEvent) = delete;
};
