#pragma once
#include <memory>
class CPrtMsg;
class CListener;
class CSSLServer;
class CPassiveSock;
class ISocketStream;

class CTransport
{
private:
	std::unique_ptr <CSSLServer>  SSLServer;
	std::unique_ptr <CPassiveSock> PassiveSock;
public:
	ISocketStream * SocketStream;
	bool IsConnected;
	int Recv(void * const lpBuf, const int Len);
	CTransport(SOCKET s, CListener * Listener);
	virtual ~CTransport();
	std::unique_ptr<CListener> m_Listener;
	int Send(const void * const lpBuf, const int RequestedLen);
};
