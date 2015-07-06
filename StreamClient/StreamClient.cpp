// StreamClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "ActiveSock.h"
#include "SSLClient.h"
#include "EventWrapper.h"
#include <atlconv.h>
#include <string>
#include <iostream>
#include "SSLHelper.h"

using namespace std;

// Given a pointer to a certificate context, return the certificate name (the friendly name if there is one, the subject name otherwise).

CString GetCertName(PCCERT_CONTEXT pCertContext)
{
   CString certName;
   auto good = CertGetNameString(pCertContext, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, NULL, certName.GetBuffer(128), certName.GetAllocLength() - 1);
   certName.ReleaseBuffer();
   if (good)
      return certName;
   else
      return L"<unknown>";
}

// Function to evaluate the certificate returned from the server
// if you want to keep it around call CertDuplicateCertificateContext, then CertFreeCertificateContext to free it
bool CertAcceptable(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)
{
   if (trusted)
      cout << "A trusted";
   else
      cout << "An untrusted";
   wcout << " server certificate was returned for ";
   if (matchingName)
      cout << "the expected";
   else
      cout << "an unexpected";
   wcout << " name: " << (LPCWSTR)GetCertName(pCertContext) << endl; // wcout for WCHAR* handling
   if (false && debug && pCertContext)
      ShowCertInfo(pCertContext, _T("Client Received Server Certificate"));
   return true; // Any certificate will do
}

// This will get called once, or twice, the first call with pIssuerListInfo NULL, which can 
// return any certificate it likes, or none at all. If it returns one, that will be sent to the server.
// If that call did not return a certificate, the procedure may be called again if the server requests a 
// client certificate, whatever is returned (including null) is sent to the server which gets to decide
// whether or not it is acceptable.

SECURITY_STATUS SelectClientCertificate(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx * pIssuerListInfo)
{
   SECURITY_STATUS Status = SEC_E_OK;
   if (pIssuerListInfo)
      Status = CertFindFromIssuerList(pCertContext, *pIssuerListInfo);
   // Comment out the next 2 lines to wait until you have an explicit call from the server 
   // requesting a client certificate and providing pIssuerListInfo
   //if (FAILED(Status) || !pCertContext)
   //   Status = CertFindClient(pCertContext);
   if (pIssuerListInfo)
      cout << "Client certificate requested with issuer list";
   else
      cout << "Client certificate requested without issuer list";
   if (pCertContext)
      wcout << ", selected name: " << (LPCWSTR)GetCertName(pCertContext) << endl; // wcout for WCHAR* handling
   else
      cout << ", none found." << endl;
   if (false && debug && pCertContext)
      ShowCertInfo(pCertContext, _T("Client certificate being returned"));
   return Status;
}

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
      pSSLClient->ServerCertAcceptable = CertAcceptable;
      pSSLClient->SelectClientCertificate = SelectClientCertificate;
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
		   pSSLClient->Close();
		}
		else
		{
			cout << "SSL client initialize failed" << endl;
		}
		::SetEvent(ShutDownEvent);
      pActiveSock->Close();
   }
	else
	{
		cout << "Socket failed to connect to server" << endl;
	}
	cout << "Press any key to exit" << endl;
	getchar();
	return 0;
}

