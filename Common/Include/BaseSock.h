#pragma once
#include "ISocketStream.h"
class CBaseSock: public virtual ISocketStream
{
public:
	// Constructor
	CBaseSock() = delete;
	CBaseSock(CBaseSock&) = delete;
	CBaseSock(CBaseSock&&) = delete;
	explicit CBaseSock(HANDLE StopEvent);
	explicit CBaseSock(SOCKET s, HANDLE StopEvent);
	~CBaseSock();
	bool Connect(LPCTSTR HostName, USHORT PortNumber);

	virtual void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds);
	virtual int GetRecvTimeoutSeconds() const;
	virtual void SetSendTimeoutSeconds(int NewSendTimeoutSeconds);
	virtual int GetSendTimeoutSeconds() const;
	virtual void StartRecvTimer();
	virtual void StartSendTimer();

	BOOL ShutDown(int nHow = SD_BOTH);
	// Methods used for ISocketStream
	virtual int RecvMsg(LPVOID lpBuf, const size_t Len, const size_t MinLen = 1);
	virtual int SendMsg(LPCVOID lpBuf, const size_t Len);
	virtual int RecvPartial(LPVOID lpBuf, const size_t Len);
	virtual int SendPartial(LPCVOID lpBuf, const size_t Len);
	virtual DWORD GetLastError() const;
	virtual HRESULT Disconnect();

protected:
	SOCKET ActualSocket{ INVALID_SOCKET };
	HANDLE m_hStopEvent{ nullptr };

private:
	HRESULT Setup();
	bool CloseAndInvalidateSocket();
	DWORD LastError = 0;
	bool RecvInitiated = false;
	WSAEVENT write_event{ nullptr };
	WSAEVENT read_event{ nullptr };
	WSAOVERLAPPED os{};
	CTime RecvEndTime;
	CTime SendEndTime;
	int SendTimeoutSeconds{ 1 }, RecvTimeoutSeconds{ 1 }; // Default timeout is 1 seconds, encourages callers to set it
};

