#pragma once
class ISocketStream
{
protected:
	~ISocketStream(void) {}; // Disallow polymorphic destruction
public:
	virtual int Recv(void * const lpBuf, const int Len) = 0;
	virtual int Send(const void * const lpBuf, const int Len) = 0;
	virtual int GetLastError(void) = 0;
	virtual HRESULT Disconnect(void) = 0;
};

