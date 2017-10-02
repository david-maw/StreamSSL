#include "stdafx.h"
#include "SSLHelper.h"

using namespace std;

// This method is called when the first client tries to connect in order to allow a certificate to be selected to send to the client
// It has to wait for the client connect request because the client tells the server what identity it expects it to present
// This is called SNI (Server Name Indication) and it is a relatively new SSL feature
SECURITY_STATUS SelectServerCert(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)
{
	SECURITY_STATUS status;
	status = CertFindCertificateBySignature(pCertContext, 
	   "a9 f4 6e bf 4e 1d 6d 67 2d 2b 39 14 ee ee 58 97 d1 d7 e9 d0", true);  // "true" looks in user store, "false", or nothing looks in machine store
   if (!pCertContext) // If we don't already have a certificate, try and select a likely looking one
	   status = CertFindServerCertificateByName(pCertContext, pszSubjectName); // Add "true" to look in user store, "false", or nothing looks in machine store
   if (pCertContext)
      wcout << "Server certificate requested for " << pszSubjectName << ", found \"" << (LPCWSTR)GetCertName(pCertContext) << "\"" << endl;
   return status;
}


// This methood is called when a client connection is offered, it returns an indication of whether the certificate (or lack of one) is acceptable 
bool ClientCertAcceptable(PCCERT_CONTEXT pCertContext, const bool trusted)
{
   if (trusted)
      cout << "A trusted";
   else
      cout << "An untrusted";
   wcout << " client certificate was returned for \"" << (LPCWSTR)GetCertName(pCertContext) << "\"" << endl;
   return NULL != pCertContext; // Meaning any certificate is fine, trusted or not, but there must be one
}

int _tmain(int argc, TCHAR* argv[], TCHAR* envp[])
{
	if (!IsUserAdmin())
		cout << "WARNING: The server is not running as an administrator." << endl;
	const int Port = 41000;
	unique_ptr<CListener> Listener(new CListener());
   Listener->SelectServerCert = SelectServerCert;
   Listener->ClientCertAcceptable = ClientCertAcceptable;
	Listener->Initialize(Port);
	cout << "Starting to listen on port " << Port << ", will find certificate for first connection." << endl;
	Listener->BeginListening([](ISocketStream * const StreamSock){
		// This is the code to be executed each time a socket is opened
		CString s;
		char MsgText[100]; // Because the simple text messages we exchange are char not wchar

		cout << "A connection has been made, worker started, sending hello" << endl;
		StreamSock->Send("Hello from server", 17);
		int len = StreamSock->Recv(MsgText, sizeof(MsgText) - 1);
		if (len > 0)
		{
			MsgText[len] = '\0'; // Terminate the string, for convenience
			cout << "Received " << MsgText << endl;
			cout << "Sending goodbye from server" << endl;
			StreamSock->Send("Goodbye from server", 19);
		}
		else
			cout << "No response data received " << endl;
      cout << "Exiting worker" << endl << endl;
	});

	cout << "Listening, press any key to exit.\n" << endl;
	getchar();
	Listener->EndListening();
	return 0;
}
