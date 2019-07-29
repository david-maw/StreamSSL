#pragma once
#include "BaseSock.h"
#include "ISocketStream.h"

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock


class CPassiveSock : private virtual CBaseSock, public ISocketStream
{
public:
	explicit CPassiveSock(SOCKET, HANDLE);
	virtual ~CPassiveSock();
	int ReceiveBytes(void * const lpBuf, const size_t Len);
	int SendBytes(const void * const lpBuf, const size_t Len);

	// ISocketStream interface, these items have to be defined so a cast to ISocketStream works
	DWORD GetLastError() const override; // Has to be declared so that a castt to 
	// Receives exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int RecvPartial(LPVOID lpBuf, const size_t Len) override;
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendPartial(LPCVOID lpBuf, const size_t Len) override;
	HRESULT Disconnect() override; // Returns S_OK if the close worked
	void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds) override;
	int GetRecvTimeoutSeconds() const override;
	void SetSendTimeoutSeconds(int NewSendTimeoutSeconds) override;
	int GetSendTimeoutSeconds() const override;
	void StartRecvTimer() override;
	void StartSendTimer() override;

protected:
	using CBaseSock::ActualSocket;
	using CBaseSock::m_hStopEvent;

private:
};

