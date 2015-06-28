#pragma once

#include <comdef.h>
#include "PassiveSock.h"
#include "ISocketStream.h"

class CPrtMsg;
class CListener;
class CSSLServer;

class CTransport  
{
private:
	CSSLServer * SSLServer;
	CPassiveSock * PassiveSock;
public:
	ISocketStream * SocketStream;
	bool IsConnected;
	int Recv(void * const lpBuf, const int Len);
	CTransport(SOCKET s, CListener * Listener);
	virtual ~CTransport();
	CListener * m_Listener;
	int Send(const void * const lpBuf, const int RequestedLen);
};
