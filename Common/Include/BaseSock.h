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
	virtual ~CBaseSock();
	bool Connect(LPCWSTR HostName, USHORT PortNumber);

	// Methods used for ISocketStream
	int Recv(LPVOID lpBuf, const size_t Len, const size_t MinLen = 1) override;
	int Send(LPCVOID lpBuf, const size_t Len) override;
	DWORD GetLastError() const override;
	HRESULT Disconnect(bool CloseUnderlyingConnection = true) override;
	void SetRecvTimeoutSeconds(int NewTimeoutSeconds, bool NewTimerAutomatic = true) override;
	int GetRecvTimeoutSeconds() const override;
	void SetSendTimeoutSeconds(int NewTimeoutSeconds, bool NewTimerAutomatic = true) override;
	int GetSendTimeoutSeconds() const override;
	void StartRecvTimer() override;
	void StartSendTimer() override;

	virtual int RecvPartial(LPVOID lpBuf, const size_t Len);
	virtual int SendPartial(LPCVOID lpBuf, const size_t Len);

protected:
	SOCKET ActualSocket{ INVALID_SOCKET };
	HANDLE m_hStopEvent{ nullptr };
	virtual void StartRecvTimerInternal();
	virtual void StartSendTimerInternal();

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
	bool RecvTimerAutomatic = true;
	bool SendTimerAutomatic = true;
	int SendTimeoutSeconds{ 1 }, RecvTimeoutSeconds{ 1 }; // Default timeout is 1 seconds, encourages callers to set it
};
