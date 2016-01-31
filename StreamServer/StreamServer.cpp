#include "stdafx.h"
#include "Listener.h"
#include "ISocketStream.h"
#include "SSLHelper.h"
#include <memory>

using namespace std;

CString GetCertName(PCCERT_CONTEXT pCertContext)
{
   CString certName;
   auto good = CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, certName.GetBuffer(128), certName.GetAllocLength()-1);
   certName.ReleaseBuffer();
   if (good)
      return certName;
   else
      return L"<unknown>";
}

SECURITY_STATUS SelectServerCert(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)
{
   SECURITY_STATUS status = CertFindServerByName(pCertContext, pszSubjectName); // Add "true" to look in user store, "false", or nothing looks in machine store
   if (pCertContext)
      wcout << "Server certificate requested for " << pszSubjectName << ", found " << (LPCWSTR)GetCertName(pCertContext) << endl;
   return status;
}

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
	cout << "Starting to listen on port " << Port << endl;
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
