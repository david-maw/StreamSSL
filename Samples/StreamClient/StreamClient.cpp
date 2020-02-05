// StreamClient.cpp : This is a sample calling program that uses the SSL client side capabilities.
//

#include "pch.h"
#include "framework.h"

#include "Utilities.h"
#include "ActiveSock.h"
#include "SSLClient.h"
#include "EventWrapper.h"
#include "CertHelper.h"

#include <iostream>
#include <iomanip>
#include <string>

using namespace std;

// Function to evaluate the certificate returned from the server
// if you want to keep it around call CertDuplicateCertificateContext, then CertFreeCertificateContext to free it
bool CertAcceptable(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)
{
	if (trusted)
		cout << "A trusted";
	else
		cout << "An untrusted";
	wcout << " server certificate called \"" << GetCertName(pCertContext).c_str() << "\" was returned with a name "; // wcout for WCHAR* handling
	if (matchingName)
		cout << "match" << endl;
	else
		cout << "mismatch" << endl;
	if (g_ShowCertInfo && debug && pCertContext)
		ShowCertInfo(pCertContext, L"Client Received Server Certificate");
	return true; // Any certificate will do
}

// This will get called once, or twice, the first call with "Required" false, which can return any
// certificate it likes, or none at all. If it returns one, that will be sent to the server.
// If that call did not return an acceptable certificate, the procedure may be called again if the server requests a 
// client certificate, whatever is returned on the first call (including null) is sent to the server which gets to decide
// whether or not it is acceptable. If there is a second call (which will have "Required" true and may have 
// pIssuerListInfo non-NULL) it MUST return a certificate or the handshake will fail.

SECURITY_STATUS SelectClientCertificate(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx * pIssuerListInfo, bool Required)
{
	SECURITY_STATUS Status = SEC_E_CERT_UNKNOWN;

	if (Required)
	{
		// A client certificate must be returned or the handshake will fail
		if (pIssuerListInfo)
		{
			if (pIssuerListInfo->cIssuers == 0)
				cout << "Client certificate required, issuer list is empty";
			else
			{
				cout << "Client certificate required, issuer list provided";
				Status = CertFindFromIssuerList(pCertContext, *pIssuerListInfo);
				if (!pCertContext)
					cout << " but no certificates matched";
			}
		}
		if (!pCertContext)
			Status = CertFindClientCertificate(pCertContext); // Select any valid certificate, regardless of issuer
		 // If a search for a required client certificate failed, just make one
		if (!pCertContext)
		{
			cout << ", none found, creating one";
			pCertContext = CreateCertificate(false, (GetCurrentUserName() + L" at " + GetHostName()).c_str(), L"StreamSSL client", nullptr, true);
			if (pCertContext)
				Status = S_OK;
			else
			{
				DWORD LastError = GetLastError();
				wcout << endl << L"**** Error 0x" << std::hex << std::setw(8) << std::setfill(L'0') << LastError 
					<< L"(" << WinErrorMsg(LastError) << L") in CreateCertificate" << endl
					<< "Client certificate";
				Status = HRESULT_FROM_WIN32(LastError);
			}
		}
	}
	else
	{
		cout << "Optional client certificate requested (without issuer list)";
		// Enable the next line to preemptively guess at an appropriate certificate 
		if (false && FAILED(Status))
			Status = CertFindClientCertificate(pCertContext); // Select any valid certificate
	}
	if (pCertContext)
		wcout << ", selected name: " << GetCertName(pCertContext).c_str() << endl; // wcout for WCHAR* handling
	else
		cout << ", no certificate found." << endl;
	if (g_ShowCertInfo && debug && pCertContext)
		ShowCertInfo(pCertContext, L"Client certificate being returned");
	return Status;
}

BOOL FlushConsoleInputBufferAlternate(HANDLE h)
{	// Needed because FlushConsoleInputBuffer did not work in Windows 10 as of October 2017
	// but by July 2018 it was working again, so, for example version 10.0.17134 works.
	INPUT_RECORD inRec;
	DWORD recsRead;
	BOOL rslt = TRUE;
	while (rslt && ((rslt = GetNumberOfConsoleInputEvents(h, &recsRead)) == TRUE) && (recsRead > 0))
		rslt = ReadConsoleInput(h, &inRec, 1, &recsRead);
	return rslt;
}

WORD WaitForAnyKey(DWORD TimeOutMilliSeconds = 5000)
{
	//printf("Press a key within %i ms\n", TimeOutMilliSeconds);
	HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
	ULONGLONG endTime = GetTickCount64() + TimeOutMilliSeconds;
	// flush to remove existing events
	if (!FlushConsoleInputBufferAlternate(hStdin))
		cout << "FlushConsoleInputBuffer failed LastError=" << GetLastError() << endl;
	// Now wait for input or timeout
	while (WaitForSingleObject(hStdin, (DWORD)max(0, endTime - GetTickCount64())) == WAIT_OBJECT_0)
	{
		INPUT_RECORD inRec;
		DWORD recsRead = 0;
		while (GetNumberOfConsoleInputEvents(hStdin, &recsRead) && (recsRead > 0))
		{
			ReadConsoleInput(hStdin, &inRec, 1, &recsRead);
			if (inRec.EventType == KEY_EVENT && inRec.Event.KeyEvent.bKeyDown == 0)
				return inRec.Event.KeyEvent.wVirtualKeyCode; // a key was released, return its identity
		}
	}
	//printf("Done waiting for key release, continuing\n");
	//Sleep(2000); // Enough time to read the message
	return 0;
}

int wmain(int argc, WCHAR * argv[])
{
	//_CrtSetBreakAlloc(225); // Catch a memory leak
	std::wstring HostName(GetHostName(ComputerNameDnsFullyQualified));
	if (argc >= 2)
		HostName = std::wstring(argv[1]);
	int Port = 41000;

	CEventWrapper ShutDownEvent;

	auto pActiveSock = make_unique<CActiveSock>(ShutDownEvent);
	pActiveSock->SetRecvTimeoutSeconds(30);
	pActiveSock->SetSendTimeoutSeconds(60);
	wcout << "StreamClient version " << GetVersionText() << " connecting to " << HostName.c_str() << ":" << Port << endl;
	bool b = pActiveSock->Connect(HostName.c_str(), static_cast<USHORT>(Port));
	if (b)
	{
		// Drive the server side by sending messages it expects
		cout << "Socket connected to server, initializing SSL" << endl;
		auto pSSLClient = make_unique<CSSLClient>(pActiveSock.get());
		pSSLClient->ServerCertAcceptable = CertAcceptable;
		pSSLClient->SelectClientCertificate = SelectClientCertificate;
		HRESULT hr = pSSLClient->Initialize(HostName.c_str());
		if (SUCCEEDED(hr))
		{
			cout << "Connected, cert name matches=" << pSSLClient->getServerCertNameMatches()
				<< ", cert is trusted=" << pSSLClient->getServerCertTrusted() << endl;
			cout << "Sending greeting" << endl;
			CStringA sentMsg("Hello from client");
			if (pSSLClient->Send(sentMsg.GetBuffer(), sentMsg.GetLength()) != sentMsg.GetLength())
				cout << "Wrong number of characters sent" << endl;
			cout << "Sending second greeting" << endl;
			sentMsg ="Hello again from client";
			if (pSSLClient->Send(sentMsg.GetBuffer(), sentMsg.GetLength()) != sentMsg.GetLength())
				cout << "Wrong number of characters sent" << endl;
			cout << "Listening for message from server" << endl;
			int len = 0;
			char Msg[100];
			if (0 < (len = pSSLClient->Recv(Msg, sizeof(Msg))))
			{
				cout << "Received '" << CStringA(Msg, len) << "'" << endl;
				// Receive a second message, ignore errors
				if (0 < (len = pSSLClient->Recv(Msg, sizeof(Msg))))
					cout << "Received '" << CStringA(Msg, len) << "'" << endl;
				cout << "Shutting down SSL" << endl;
				::Sleep(1000); // Give the next message a chance to arrive at the server separately
				pSSLClient->Disconnect(false);
				// The TCP connection still exists and can be used to send messages, though
				// this is rarely done, here's an example of doing it
				cout << "Sending first unencrypted data message" << endl;
				sentMsg = "First block of unencrypted data from client";
				if (pActiveSock->Send(sentMsg.GetBuffer(), sentMsg.GetLength()) != sentMsg.GetLength())
					cout << "Wrong number of characters sent" << endl;
				else
				{
					cout << "Sleeping before sending second unencrypted data message" << endl;
					::Sleep(6000); // Give the previous message time to arrive at the server and for the server socket to receive it and hand to to the caller
					cout << "Sending second unencrypted data message" << endl;
					sentMsg = "Second block of unencrypted data from client";
					if (pActiveSock->Send(sentMsg.GetBuffer(), sentMsg.GetLength()) != sentMsg.GetLength())
						cout << "Wrong number of characters sent" << endl;
					else
					{
						cout << "Sleeping before sending termination to give the last message time to arrive" << endl;
						::Sleep(3000); // Give the previous message time to arrive at the server and for the server socket to receive it and hand to to the caller
					}
				}
			}
			else
				cout << "Recv reported an error" << endl;
		}
		else
		{
			wcout << L"SSL client initialize failed: " << WinErrorMsg(hr) << endl;
		}
		::SetEvent(ShutDownEvent); // Used to early exit any async send or receive that are in process
		pActiveSock->Disconnect();
	}
	else
	{
		cout << "Socket failed to connect to server" << endl;
	}
	cout << "Press any key to pause, Q to exit immediately" << endl;
	WORD key = WaitForAnyKey(30000);
	if (!(key == 'Q' || key == 0))
	{
		cout << "The program will pause until you press enter" << endl;
		key = (WORD)getchar(); // Assign result to avoid warning
	}
	return 0;
}
