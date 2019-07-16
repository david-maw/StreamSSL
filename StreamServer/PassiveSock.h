#pragma once
#include "ISocketStream.h"

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock



class CPassiveSock : public ISocketStream
{
public:
	CPassiveSock(SOCKET, HANDLE);
	virtual ~CPassiveSock();
	int GetLastError() override;
	void SetTimeoutSeconds(int NewTimeoutSeconds);
	void ArmRecvTimer();
	void ArmSendTimer();
	int RecvPartial(void * const lpBuf, const size_t Len) override;
	int SendPartial(const void * const lpBuf, const size_t Len) override;
	int ReceiveBytes(void * const lpBuf, const size_t nBufLen);
	int SendBytes(const void * const lpBuf, const size_t Len);
	BOOL ShutDown(int nHow = SD_SEND);
	HRESULT Disconnect() override;

private:
	CTime RecvEndTime;
	CTime SendEndTime;
	WSAEVENT write_event;
	WSAEVENT read_event;
	WSAOVERLAPPED os;
	bool RecvInitiated = false;
	SOCKET ActualSocket;
	int LastError = 0;
	int TimeoutSeconds = 1;
	HANDLE m_hStopEvent;
};

