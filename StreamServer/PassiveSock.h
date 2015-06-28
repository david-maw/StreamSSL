#pragma once
#include <atltime.h>
#include "ISocketStream.h"

/////////////////////////////////////////////////////////////////////////////
// CPassiveSock



class CPassiveSock : public ISocketStream
{
public:
	CPassiveSock(SOCKET, HANDLE);
	virtual ~CPassiveSock();
	int GetLastError();
	void SetTimeoutSeconds(int NewTimeoutSeconds);
	virtual int Recv(void * const lpBuf, const int Len);
	virtual int Send(const void * const lpBuf, const int Len);
	int ReceiveBytes(void * const lpBuf, const int nBufLen);
	int SendBytes(const void * const lpBuf, const int Len);
	BOOL ShutDown(int nHow = SD_SEND);
	virtual HRESULT Disconnect(void);

private:
	CTime RecvEndTime;
	CTime SendEndTime;
	WSAEVENT write_event;
	WSAEVENT read_event;
	WSAOVERLAPPED os;
	bool RecvInitiated;
	SOCKET ActualSocket;
	int LastError;
	int TimeoutSeconds;
	HANDLE m_hStopEvent;
};

