#pragma once
#include "BaseSock.h"
// #include "ISocketStream.h" not needed

/////////////////////////////////////////////////////////////////////////////
// CActiveSock


class CActiveSock : private CBaseSock //, public ISocketStream not needed
{
public:
	explicit CActiveSock(HANDLE StopEvent);
	virtual ~CActiveSock();
	bool Connect(LPCTSTR HostName, USHORT PortNumber);
	void SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds);
	int GetRecvTimeoutSeconds() const;
	void SetSendTimeoutSeconds(int NewSendTimeoutSeconds);
	int GetSendTimeoutSeconds() const;
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	int RecvMsg(LPVOID lpBuf, const size_t Len);
	// Sends exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendMsg(LPCVOID lpBuf, const size_t Len);
	// ISocketStream interface
	using CBaseSock::GetLastError;
	// Receives exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int RecvPartial(LPVOID lpBuf, const size_t Len) override;
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendPartial(LPCVOID lpBuf, const size_t Len) override;
	HRESULT Disconnect() override; // Returns S_OK if the close worked

private:
	bool CloseAndInvalidateSocket();
	int SendTimeoutSeconds{ 1 }, RecvTimeoutSeconds{ 1 }; // Default timeout is 1 seconds, encourages callers to set it
};