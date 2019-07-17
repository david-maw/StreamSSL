#pragma once
#include <memory>
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
  bool IsConnected{ false };
	int Recv(void * const lpBuf, const int Len);
	CTransport(SOCKET s, CListener * Listener);
	virtual ~CTransport();
	CListener* m_Listener;
	int Send(const void * const lpBuf, const int RequestedLen);
};
