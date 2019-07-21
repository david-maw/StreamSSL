#pragma once
#include "ISocketStream.h"

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock


class CPassiveSock : public ISocketStream
{
public:
	explicit CPassiveSock(SOCKET, HANDLE);
	virtual ~CPassiveSock();
	void SetTimeoutSeconds(int NewTimeoutSeconds);
	void ArmRecvTimer();
	void ArmSendTimer();
	int ReceiveBytes(void * const lpBuf, const size_t Len);
	int SendBytes(const void * const lpBuf, const size_t Len);
	BOOL ShutDown(int nHow = SD_SEND);
	// ISocketStream interface
	DWORD GetLastError() const override;
	int RecvPartial(void * const lpBuf, const size_t Len) override;
	int SendPartial(const void * const lpBuf, const size_t Len) override;
	HRESULT Disconnect() override;

private:
	CTime RecvEndTime;
	CTime SendEndTime;
	WSAEVENT write_event;
	WSAEVENT read_event;
	WSAOVERLAPPED os;
	bool RecvInitiated = false;
	SOCKET ActualSocket;
	DWORD LastError = 0;
	int TimeoutSeconds = 1;
	HANDLE m_hStopEvent;
};

