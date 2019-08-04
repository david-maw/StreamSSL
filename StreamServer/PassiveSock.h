#pragma once
#include "BaseSock.h"

class CPassiveSock : public CBaseSock
{
public:
	// Allow creation from a received SOCKET
	explicit CPassiveSock(SOCKET, HANDLE);
	// Disallow creation of an active socket
	CPassiveSock(HANDLE) = delete;
	// Disconnect has different meaning in client and server sockets, annoyingly...
	HRESULT Disconnect();
private:
	// Disallow the active socket connect function
	using CBaseSock::Connect;
};

