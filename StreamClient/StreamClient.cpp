// StreamClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ActiveSock.h"
#include "SSLClient.h"
#include "EventWrapper.h"
#include <atlconv.h>
#include <string>
#include <iostream>

using namespace std;

int _tmain(int argc, _TCHAR* argv[])
{
	CString HostName("localhost");
   if (argc >= 2)
      HostName.SetString(argv[1]);
	int Port = 41000;

	CEventWrapper ShutDownEvent;

	CActiveSock * pActiveSock = new CActiveSock(ShutDownEvent);
	CSSLClient * pSSLClient = nullptr;
	pActiveSock->SetRecvTimeoutSeconds(30);
	pActiveSock->SetSendTimeoutSeconds(60);
	wcout << "Connecting to " << HostName.GetString() << ":" << Port << endl;
	bool b = pActiveSock->Connect(HostName, Port);
	if (b)
	{
		cout << "Socket connected to server, initializing SSL" << endl;
		char Msg[100];
		pSSLClient = new CSSLClient(pActiveSock);
		b = SUCCEEDED(pSSLClient->Initialize(ATL::CT2W(HostName)));
		if (b)
		{
			cout << "Connected, cert name matches=" << pSSLClient->getServerCertNameMatches()
				<< ", cert is trusted=" << pSSLClient->getServerCertTrusted() << endl;
			cout << "Sending greeting" << endl;
			if (pSSLClient->SendPartial("Hello from client", 17) != 17)
				cout << "Wrong number of characters sent" << endl;
			cout << "Listening for messages from server" << endl;
			int len = 0;
			while (0 < (len = pSSLClient->RecvPartial(Msg, sizeof(Msg))))
				cout << "Received " << CStringA(Msg, len) << endl;
		}
		else
		{
			cout << "SSL client initialize failed" << endl;
		}
		::SetEvent(ShutDownEvent);
		pSSLClient->Close();
	}
	else
	{
		cout << "Socket failed to connect to server" << endl;
	}
	cout << "Press any key to exit" << endl;
	getchar();
	return 0;
}

