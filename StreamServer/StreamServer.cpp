#include "stdafx.h"
#include "Listener.h"
#include "ISocketStream.h"
#include <memory>

using namespace std;

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	if (!IsUserAdmin())
		cout << "WARNING: The server is not running as an administrator." << endl;
	const int Port = 41000;
	unique_ptr<CListener> Listener(new CListener());
	Listener->Initialize(Port);
	cout << "Starting to listen on port " << Port << endl;
	Listener->BeginListening([](ISocketStream * const StreamSock){
		// This is the code to be executed each time a socket is opened
		CString s;
		char MsgText[100]; // Because the simple text messages we exchange are char not wchar

		cout << "A socket has been opened, sending hello" << endl;
		StreamSock->Send("Hello from server", 17);
		int len = StreamSock->Recv(MsgText, sizeof(MsgText) - 1);
		if (len > 0)
		{
			MsgText[len] = '\0'; // Terminate the string, for convenience
			cout << "Received " << MsgText << endl;
			cout << "Sending goodbye from server" << endl << endl;
			StreamSock->Send("Goodbye from server", 19);
		}
		else
			cout << "No response data received " << endl;
	});

	cout << "Listening, press any key to exit.\n" << endl;
	getchar();
	Listener->EndListening();
	return 0;
}
