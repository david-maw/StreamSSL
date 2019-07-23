#pragma once
#include "BaseSock.h"
#include "ISocketStream.h"

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock


class CPassiveSock : private CBaseSock, public ISocketStream
{
public:
	explicit CPassiveSock(SOCKET, HANDLE);
	virtual ~CPassiveSock();
	using CBaseSock::SetTimeoutSeconds;
	using CBaseSock::StartRecvTimer;
	using CBaseSock::StartSendTimer;
	int ReceiveBytes(void * const lpBuf, const size_t Len);
	int SendBytes(const void * const lpBuf, const size_t Len);
	// BOOL ShutDown(int nHow = SD_SEND); // ShutDown is no longer public
	// ISocketStream interface, these items have to be defined so a cast to ISocketStream works
	DWORD GetLastError() const override; // Has to be declared so that a castt to 
	// Receives exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int RecvPartial(LPVOID lpBuf, const size_t Len) override;
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendPartial(LPCVOID lpBuf, const size_t Len) override;
	HRESULT Disconnect() override; // Returns S_OK if the close worked

protected:
	using CBaseSock::ActualSocket;
	using CBaseSock::m_hStopEvent;

private:
};

