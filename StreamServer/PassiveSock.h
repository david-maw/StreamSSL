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

	// ISocketStream interface, these items have to be defined so a cast to ISocketStream works
	DWORD GetLastError() const override; 
	int RecvMsg(LPVOID lpBuf, const size_t Len, const size_t MinLen = 1);
	int SendMsg(LPCVOID lpBuf, const size_t Len);
	int RecvPartial(LPVOID lpBuf, const size_t Len) override;
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

