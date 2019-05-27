#pragma once
#include <atltime.h>
#include "ISocketStream.h"

#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")

/////////////////////////////////////////////////////////////////////////////
// CActiveSock


class CActiveSock : public ISocketStream
{
public:
	CActiveSock(HANDLE StopEvent);
	virtual ~CActiveSock();
	bool Connect(LPCTSTR HostName, USHORT PortNumber);
	void SetRecvTimeoutSeconds(int NewTimeoutSeconds);
	int GetRecvTimeoutSeconds();
	void SetSendTimeoutSeconds(int NewTimeoutSeconds);
	int GetSendTimeoutSeconds();
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	int RecvPartial(LPVOID lpBuf, const ULONG Len);
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendPartial(LPCVOID lpBuf, const ULONG Len);
	// Receives exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int RecvMsg(LPVOID lpBuf, const ULONG Len);
	// Sends exactly Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	int SendMsg(LPCVOID lpBuf, const ULONG Len);
	BOOL ShutDown(int nHow = SD_BOTH);
	DWORD GetLastError();
	bool Close(void); // Returns true if the close worked

private:
	CTime RecvEndTime;
	CTime SendEndTime;
	static WSADATA WsaData;
	WSAEVENT write_event;
	WSAEVENT read_event;
	WSAOVERLAPPED os{};
	bool RecvInitiated = false;
	SOCKET ActualSocket;
	DWORD LastError = 0;
	int SendTimeoutSeconds, RecvTimeoutSeconds;
	HANDLE m_hStopEvent;
};