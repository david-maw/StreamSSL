#include "stdafx.h"
#include "SSLHelper.h"
#include "CertHelper.h"
#include "Listener.h"
#include "ISocketStream.h"

using namespace std;

// This method is called when the first client tries to connect in order to allow a certificate to be selected to send to the client
// It has to wait for the client connect request because the client tells the server what identity it expects it to present
// This is called SNI (Server Name Indication) and it is a relatively new SSL feature
SECURITY_STATUS SelectServerCert(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)
{
	SECURITY_STATUS status;

	status = CertFindServerCertificateUI(pCertContext, pszSubjectName, false);
	if (!pCertContext) // If we don't already have a certificate, try and select a specific one
		status = CertFindCertificateBySignature(pCertContext,
			"a9 f4 6e bf 4e 1d 6d 67 2d 2b 39 14 ee ee 58 97 d1 d7 e9 d0", true);  // "true" looks in user store, "false", or nothing looks in machine store
	if (!pCertContext) // If we don't already have a certificate, try and select a likely looking one
		status = CertFindServerCertificateByName(pCertContext, pszSubjectName); // Add "true" to look in user store, "false", or nothing looks in machine store
	if (pCertContext)
		wcout << "Server certificate requested for " << pszSubjectName << ", found \"" << (LPCWSTR)GetCertName(pCertContext) << "\"" << endl;
	// Uncomment the next 2 lines if you want to see details of the selected certificate
	//if (pCertContext)
	//   ShowCertInfo(pCertContext, "Server Certificate In Use");
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

// Run arbitrary code and return process information
bool RunApp(WCHAR * app, PROCESS_INFORMATION& pi)
{ // Not strictly needed but it makes testing easier
	STARTUPINFO si = {};
	si.cb = sizeof si;

	if (CreateProcess(NULL, app, 0, FALSE, 0, CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
		return true;
	else
	{
		cerr << "CreateProcess failed (" << GetLastError() << ").\n";
		return false;
	}
}
// Run the sample client application just to simplify testing (that way you needn't run both server and client separately)
void RunClient(CString toHost = L"", PROCESS_INFORMATION * ppi = NULL)
{
	cout << "Initiating a client instance for testing.\n" << endl;
	WCHAR acPathName[MAX_PATH + 1];
	GetModuleFileName(NULL, acPathName, sizeof(acPathName));
	CString appName(acPathName);
	int len = appName.ReverseFind(L'\\');
	appName = appName.Left(len + 1) + L"StreamClient.exe " + toHost;
	PROCESS_INFORMATION pi = {}, *localPpi = ppi ? ppi : &pi; // Just use a local one if one is not passed

	if (RunApp(appName.GetBuffer(), *localPpi) && !ppi)
	{
		cout << "Waiting on StreamClient" << endl;
		WaitForSingleObject(pi.hProcess, INFINITE);
		wcout << "Client completed." << endl;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}

// Main method, called first by the operating system when the codefile is run
int _tmain(int argc, WCHAR* argv[], WCHAR* envp[])
{
	if (!IsUserAdmin())
		cout << "WARNING: The server is not running as an administrator." << endl;
	const int Port = 41000;
	auto Listener = std::make_unique<CListener>();
	Listener->SelectServerCert = SelectServerCert;
	Listener->ClientCertAcceptable = ClientCertAcceptable;
	Listener->Initialize(Port);
	cout << "Starting to listen on port " << Port << ", will find certificate for first connection." << endl;
	Listener->BeginListening([](ISocketStream * const StreamSock) {
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

	PROCESS_INFORMATION pi = {};

	RunClient("localhost", &pi); // run a client point it at "localhost"
	cout << "Waiting on StreamClient to localhost" << endl;
	WaitForSingleObject(pi.hProcess, INFINITE);
	cout << "Client completed." << endl;
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	RunClient(); // run a second copy, but let it default the host name

	cout << "Listening for a client connection, press enter key to terminate.\n" << endl;
	getchar();
	Listener->EndListening();
	return 0;
}