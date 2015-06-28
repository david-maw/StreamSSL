#pragma once
class ISocketStream
{
public:
   // Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	virtual int RecvPartial(LPVOID lpBuf, const ULONG Len) = 0;
   // Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	virtual int SendPartial (LPCVOID lpBuf, const ULONG Len) = 0;
	virtual DWORD GetLastError() = 0;
	virtual bool Close () = 0; // Returns true if the close worked
};

