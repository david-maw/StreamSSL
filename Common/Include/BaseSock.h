#pragma once
class CBaseSock
{
protected:
	// Constructor
	CBaseSock(HANDLE StopEvent);
	~CBaseSock();

	virtual void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds);
	virtual int GetRecvTimeoutSeconds() const;
	virtual void SetSendTimeoutSeconds(int NewSendTimeoutSeconds);
	virtual int GetSendTimeoutSeconds() const;
	virtual void StartRecvTimer();
	virtual void StartSendTimer();

	BOOL ShutDown(int nHow = SD_BOTH); // will eventually be private, once all refernces move to this class 
	// Methods used for ISocketStream
	virtual int RecvMsg(LPVOID lpBuf, const size_t Len);
	virtual int SendMsg(LPCVOID lpBuf, const size_t Len);
	virtual int RecvPartial(LPVOID lpBuf, const size_t Len);
	virtual int SendPartial(LPCVOID lpBuf, const size_t Len);
	virtual DWORD GetLastError() const;
	virtual HRESULT Disconnect();

	HRESULT Setup();

	bool CloseAndInvalidateSocket();

	// Items which are protected in inherited classes
	SOCKET ActualSocket{ INVALID_SOCKET };
	HANDLE m_hStopEvent{ nullptr };

	DWORD LastError = 0;
	bool RecvInitiated = false;
	WSAEVENT write_event{ nullptr };
	WSAEVENT read_event{ nullptr };
	WSAOVERLAPPED os{};
	CTime RecvEndTime;
	CTime SendEndTime;
	int SendTimeoutSeconds{ 1 }, RecvTimeoutSeconds{ 1 }; // Default timeout is 1 seconds, encourages callers to set it
};

