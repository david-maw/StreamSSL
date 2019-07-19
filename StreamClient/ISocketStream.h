#pragma once
class ISocketStream
{
protected:
  ~ISocketStream() = default; // Disallow polymorphic destruction
public:
	// Receives up to Len bytes of data and returns the amount received - or SOCKET_ERROR if it times out
	virtual int RecvPartial(LPVOID lpBuf, const size_t Len) = 0;
	// Sends up to Len bytes of data and returns the amount sent - or SOCKET_ERROR if it times out
	virtual int SendPartial(LPCVOID lpBuf, const size_t Len) = 0;
	virtual DWORD GetLastError() = 0;
	virtual bool Close() = 0; // Returns true if the close worked
};