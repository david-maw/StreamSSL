
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#include <Windows.h>
#include <memory>
#include <iostream>

#include "EventWrapper.h"

// These are included so the headers below will compile
#include <atltime.h> // for CTime used compiling sslclient.h
#include <WinSock2.h> // For SOCKET used compiling ActiveSock.h

#include "sslclient.h"
#include "ActiveSock.h"

using namespace std;

// This is a simple example using SSLClient with a minimum of dependencies
// It connects to a web server, exchanges a couple of messages, then exits
// it works as a 32 or 64 bit build, with Unicode ar Multibyte characters
// note that the multibyte build uses a UNICODE (wide character) build of 
// SSLClient (in the SSLClient.lib file) 
int main()
{
	wstring HostName(L"www.google.com");
	int Port = 443;

	CEventWrapper ShutDownEvent;

	auto pActiveSock = make_unique<CActiveSock>(ShutDownEvent);
	pActiveSock->SetRecvTimeoutSeconds(30);
	pActiveSock->SetSendTimeoutSeconds(60);
	wcout << "StreamClient connecting to " << HostName.c_str() << ":" << Port << endl;
	bool b = pActiveSock->Connect(HostName.c_str(), static_cast<USHORT>(Port));
	if (b)
	{
		// Drive the server side by sending messages it expects
		cout << "Socket connected to server, initializing SSL" << endl;
		auto pSSLClient = make_unique<CSSLClient>(pActiveSock.get());
		HRESULT hr = pSSLClient->Initialize(HostName.c_str());
		if (SUCCEEDED(hr))
		{
			cout << "Connected, cert name matches=" << pSSLClient->getServerCertNameMatches()
				<< ", cert is trusted=" << pSSLClient->getServerCertTrusted() << endl;
			cout << "Sending greeting" << endl;
			string msg("GET HTTP/1.1\n"); // Minimum needed to get a response from a web server
			if (pSSLClient->Send(msg.c_str(), msg.length()) != msg.length())
				cout << "Wrong number of characters sent" << endl;
			cout << "Listening for message from server" << endl;
			int len = 0;
			char Msg[22];
			if (0 < (len = pSSLClient->Recv(Msg, sizeof(Msg))))
			{
				cout << "Received '" << string(Msg, len);
				if (len == sizeof(Msg)) // probably truncated
					cout << "...";
				cout << "'" << endl << "Shutting down" << endl;
			}
			else
				cout << "Recv reported an error" << endl;
		}
		else
		{
			wcout << L"SSL client initialize failed" << endl;
		}
		pActiveSock->Disconnect();
	}
	else
	{
		cout << "Socket failed to connect to server" << endl;
	}
	cout << "Press enter when finished" << endl;
	if (getchar()) 0; // The fake test is to avoid a compiler warning for ignoring the result
	return 0;
}