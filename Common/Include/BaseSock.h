#pragma once
class CBaseSock
{
protected:
	// Constructor
	CBaseSock(HANDLE StopEvent);
	~CBaseSock();

	void SetTimeoutSeconds(int NewTimeoutSeconds);
	void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds);
	int GetRecvTimeoutSeconds() const;
	void SetSendTimeoutSeconds(int NewSendTimeoutSeconds);
	int GetSendTimeoutSeconds() const;
	void StartRecvTimer();
	void StartSendTimer();

	BOOL ShutDown(int nHow = SD_BOTH); // will eventually be private, once all refernces move to this class 
	// Methods used for ISocketStream
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	virtual int RecvPartial(LPVOID lpBuf, const size_t Len);
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
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
	int TimeoutSeconds = 1;
	int SendTimeoutSeconds{ 1 }, RecvTimeoutSeconds{ 1 }; // Default timeout is 1 seconds, encourages callers to set it
};

