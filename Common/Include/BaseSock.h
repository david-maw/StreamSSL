#pragma once
class CBaseSock
{
protected:
	// Constructor
	CBaseSock(HANDLE StopEvent);
	BOOL ShutDown(int nHow = SD_BOTH); // will eventually be private, once all refernces move to this class 
	// Methods used for ISocketStream
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	virtual int RecvPartial(LPVOID lpBuf, const size_t Len) = 0;
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	virtual int SendPartial(LPCVOID lpBuf, const size_t Len) = 0;
	virtual DWORD GetLastError() const;
	virtual HRESULT Disconnect() = 0;

	SOCKET ActualSocket{ INVALID_SOCKET };
	HANDLE m_hStopEvent{ nullptr };

	DWORD LastError = 0;
	bool RecvInitiated = false;
	WSAEVENT write_event{ nullptr };
	WSAEVENT read_event{ nullptr };
	WSAOVERLAPPED os{};
};

