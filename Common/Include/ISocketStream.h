#pragma once
class ISocketStream
{
protected:
	~ISocketStream() = default; // Disallow polymorphic destruction
public:
	virtual int RecvMsg(LPVOID lpBuf, const size_t Len) = 0;
	virtual int SendMsg(LPCVOID lpBuf, const size_t Len) = 0;
	virtual int RecvPartial(LPVOID lpBuf, const size_t Len) = 0;
	virtual int SendPartial(LPCVOID lpBuf, const size_t Len) = 0;
	virtual DWORD GetLastError() const = 0;
	virtual HRESULT Disconnect() = 0; // Returns true if the close worked
	virtual void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds) = 0;
	virtual int GetRecvTimeoutSeconds() const = 0;
	virtual void SetSendTimeoutSeconds(int NewSendTimeoutSeconds) = 0;
	virtual int GetSendTimeoutSeconds() const = 0;
	virtual void StartRecvTimer() = 0;
	virtual void StartSendTimer() = 0;
};