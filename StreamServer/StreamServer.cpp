#include "pch.h"
#include "framework.h"

#include "SSLHelper.h"
#include "CertHelper.h"
#include "Listener.h"
#include "ISocketStream.h"
#include "Utilities.h"

using namespace std;

// This method is called when the first client tries to connect in order to allow a certificate to be selected to send to the client
// It has to wait for the client connect request because the client tells the server what identity it expects it to present
// This is called SNI (Server Name Indication) and it is a relatively new (it began to become available about 2005) SSL/TLS feature
SECURITY_STATUS SelectServerCert(PCCERT_CONTEXT & pCertContext, LPCTSTR pszSubjectName)
{
	SECURITY_STATUS status = SEC_E_INVALID_HANDLE;

	// The next line invokes a UI to let the user select a certificate manually
	//status = CertFindServerCertificateUI(pCertContext, pszSubjectName, false);
	if (!pCertContext) // If we don't already have a certificate, try and select a specific one
		status = CertFindCertificateBySignature(pCertContext,
			"a9 f4 6e bf 4e 1d 6d 67 2d 2b 39 14 ee ee 58 97 d1 d7 e9 d0", true);  // "true" looks in user store, "false", or nothing looks in machine store
	if (!pCertContext) // If we don't already have a certificate, try and select a likely looking one
		status = CertFindServerCertificateByName(pCertContext, pszSubjectName); // Add "true" to look in user store, "false", or nothing looks in machine store
	if (pCertContext)
		wcout << "Server certificate requested for " << pszSubjectName << ", found \"" << GetCertName(pCertContext).c_str() << "\"" << endl;
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
	wcout << " client certificate was returned for \"" << GetCertName(pCertContext).c_str() << "\"" << endl;
	return nullptr != pCertContext; // Meaning any certificate is fine, trusted or not, but there must be one
}

// This function simply runs arbitrary code and returns process information to the caller, it's just a handy utility function
bool RunApp(std::wstring app, PROCESS_INFORMATION& pi)
{ // Not strictly needed but it makes testing easier
	STARTUPINFO si = {};
	si.cb = sizeof si;
	ZeroMemory(&pi, sizeof(pi));
#pragma warning(suppress:6335)
	if (CreateProcess(nullptr, &app[0], 0, FALSE, 0, CREATE_NEW_CONSOLE, 0, 0, &si, &pi))
		return true;
	else
	{
		cerr << "CreateProcess failed (" << GetLastError() << ").\n";
		return false;
	}
}
// Run the sample client application just to simplify testing (that way you needn't run both server and client separately)
void RunClient(std::wstring toHost = L"", PROCESS_INFORMATION * ppi = nullptr)
{
	cout << "Initiating a client instance for testing.\n" << endl;
	WCHAR acPathName[MAX_PATH + 1];
	GetModuleFileName(NULL, acPathName, _countof(acPathName));
	std::wstring appName(acPathName);
	const auto len = appName.find_last_of(L'\\');
	appName = appName.substr(0, len + 1) + L"StreamClient.exe " + toHost;
	PROCESS_INFORMATION pi = {}, *localPpi = ppi ? ppi : &pi; // Just use a local one if one is not passed

	if (RunApp(appName, *localPpi) && !ppi && pi.hProcess && pi.hThread)
	{
		cout << "Waiting on StreamClient" << endl;
		WaitForSingleObject(pi.hProcess, INFINITE);
		wcout << "Client completed." << endl;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
}

// If the elapsed time since the time specified by the parameter is a second or more, display it, otherwise do nothing
void ShowDelay(CTime& Started)
{
	CTimeSpan Waited = CTime::GetCurrentTime() - Started;
	if (Waited.GetTotalSeconds() > 0)
		cout << "Waited " << Waited.GetTotalSeconds() << " seconds" << endl;
	Started = CTime::GetCurrentTime(); // Restart the timer
}

// The function called first by the operating system when the codefile is run
int _tmain(int argc, WCHAR* argv[], WCHAR* envp[])
{
	UNREFERENCED_PARAMETER(argc);
	UNREFERENCED_PARAMETER(argv);
	UNREFERENCED_PARAMETER(envp);
	if (!IsUserAdmin())
		cout << "WARNING: The server is not running as an administrator." << endl;
	const int Port = 41000;
	auto Listener = std::make_unique<CListener>();
	Listener->SelectServerCert = SelectServerCert;
	Listener->ClientCertAcceptable = ClientCertAcceptable;
	Listener->Initialize(Port);
	cout << "Starting to listen on port " << Port << ", will find certificate for first connection." << endl;
	Listener->BeginListening([](ISocketStream * const StreamSock) {
		// This is the code to be executed each time a socket is opened, basically
		// the client drives, this server code listens and responds
		std::wstring s;
		char MsgText[100]; // Because the simple text messages we exchange are char not wchar
		int len = 0;

		CStringA sentMsg("Hello from server");
		cout << "A connection has been made, worker started, sending '" << sentMsg <<"'" << endl;
		if ((len =StreamSock->SendPartial(sentMsg.GetBuffer(), sentMsg.GetLength())) != sentMsg.GetLength())
			cout << "Wrong number of characters sent" << endl;
		if (len < 0)
		{
			if (StreamSock->GetLastError() == ERROR_FILE_NOT_ENCRYPTED)
				cout << "Send cannot be used unless encrypting" << endl;
			else
				cout << "Send returned an error" << endl;
		}
		CTime Started = CTime::GetCurrentTime();
		len = StreamSock->RecvPartial(MsgText, sizeof(MsgText) - 1);
		if (len > 0)
		{
			ShowDelay(Started);
			MsgText[len] = '\0'; // Terminate the string, for convenience
			cout << "Received " << MsgText << endl;
			// At this point the client is just waiting for a message or for the connection to close
			cout << "Sending 'Goodbye from server' and listening for client messages" << endl;
			StreamSock->SendPartial("Goodbye from server", 19);
			::Sleep(1000); // Give incoming messages chance to pile up
			// Now loop receiving and decrypting messages until an error (probably SSL shutdown) is received
			while ((len = StreamSock->RecvPartial(MsgText, sizeof(MsgText) - 1)) > 0)
			{
				MsgText[len] = '\0'; // Terminate the string, for convenience
				ShowDelay(Started);
				cout << "Received '" << MsgText << "'" << endl;
			}
			if (StreamSock->GetLastError() == SEC_I_CONTEXT_EXPIRED)
			{
				cout << "Recv returned notification that SSL shut down" << endl;
				// Now loop receiving any unencrypted messages until an error (probably socket shutdown) is received
				StreamSock->SetRecvTimeoutSeconds(4);
				while (true)
				{
					if ((len = StreamSock->RecvPartial(MsgText, sizeof(MsgText) - 1)) <= 0)
					{
						if (len == INVALID_SOCKET && StreamSock->GetLastError() == ERROR_TIMEOUT)
						{
							// Just a timeout, it's ok to retry that, so just do so
							ShowDelay(Started);
							cout << "Initial receive timed out, retrying" << endl;
							if ((len = StreamSock->RecvPartial(MsgText, sizeof(MsgText) - 1)) <= 0)
								break;
						}
						else
							break;
					}
					MsgText[len] = '\0'; // Terminate the string, for convenience
					ShowDelay(Started);
					cout << "Received plaintext '" << MsgText << "'" << endl;
				}
				ShowDelay(Started);
				if (len == 0)
					cout << "Receive reported socket shutting down" << endl;
				else if (StreamSock->GetLastError() == ERROR_TIMEOUT)
					cout << "Receive timed out" << endl;
				else if (StreamSock->GetLastError() == WSA_IO_PENDING)
					cout << "Receive not completed" << endl;
				else if (StreamSock->GetLastError() == ERROR_OPERATION_ABORTED)
					cout << "Receive failed" << endl;
				else if (StreamSock->GetLastError() == WSAECONNRESET)
					cout << "The connection was reset" << endl;
				else
					cout << "Socket Recv returned an error, LastError = " << StreamSock->GetLastError() << endl;
			}
			else
				cout << "Recv returned an error" << endl;
		}
		else
			cout << "No response data received" << endl;
		cout << "Exiting worker" << endl << endl;
		cout << "Listening for client connections, press enter key to terminate." << endl << endl;
		});

	cout << "Listening for client connections." << endl << endl;

	PROCESS_INFORMATION pi = {};

	RunClient(L"localhost", &pi); // run a client point it at "localhost"
	if (pi.hProcess && pi.hThread)
	{
		cout << "Waiting on StreamClient to localhost" << endl;
		WaitForSingleObject(pi.hProcess, INFINITE);
		cout << "Client completed." << endl;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	// Run additional copies, do not wait, and let the hostname default
	PROCESS_INFORMATION pi1 = {};
	RunClient(L"", &pi1); 
	//PROCESS_INFORMATION pi2 = {};
	//RunClient(L"", &pi2);
	//PROCESS_INFORMATION pi3 = {};
	//RunClient(L"", &pi3);

	cout << "Additional test clients initiated, press enter key to terminate server." << endl << endl;
#pragma warning(suppress: 6031) // Do not care about unchecked result
	getchar();
	Listener->EndListening();
	return 0;
}