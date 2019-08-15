#pragma once
class ISocketStream
{
protected:
	~ISocketStream() = default; // Disallow polymorphic destruction
public:
	virtual int Recv(LPVOID lpBuf, const size_t Len, const size_t MinLen = 1) = 0;
	virtual int Send(LPCVOID lpBuf, const size_t Len) = 0;
	virtual DWORD GetLastError() const = 0;
	virtual HRESULT Disconnect(bool CloseUnderlyingConnection = true) = 0;
	virtual void SetRecvTimeoutSeconds(int NewTimeoutSeconds, bool NewTimerAutomatic = true) = 0;
	virtual int GetRecvTimeoutSeconds() const = 0;
	virtual void SetSendTimeoutSeconds(int NewTimeoutSeconds, bool NewTimerAutomatic = true) = 0;
	virtual int GetSendTimeoutSeconds() const = 0;
	virtual void StartRecvTimer() = 0;
	virtual void StartSendTimer() = 0;
};
