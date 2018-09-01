// StreamClient.cpp : This is a sample calling program that uses the SSL client side capabilities.
//

#include "stdafx.h"
#include "ActiveSock.h"
#include "SSLClient.h"
#include "EventWrapper.h"
#include <atlconv.h>
#include <string>
#include <iostream>
#include <iomanip>
#include "SSLHelper.h"

using namespace std;

// Function to evaluate the certificate returned from the server
// if you want to keep it around call CertDuplicateCertificateContext, then CertFreeCertificateContext to free it
bool CertAcceptable(PCCERT_CONTEXT pCertContext, const bool trusted, const bool matchingName)
{
   if (trusted)
      cout << "A trusted";
   else
      cout << "An untrusted";
   wcout << " server certificate called \"" << (LPCWSTR)GetCertName(pCertContext) << "\" was returned with a name "; // wcout for WCHAR* handling
   if (matchingName)
      cout << "match" << endl;
   else
      cout << "mismatch" << endl;
   if (false && debug && pCertContext)
      ShowCertInfo(pCertContext, _T("Client Received Server Certificate"));
   return true; // Any certificate will do
}

// This will get called once, or twice, the first call with "Required" false, which can return any
// certificate it likes, or none at all. If it returns one, that will be sent to the server.
// If that call did not return an acceptable certificate, the procedure may be called again if the server requests a 
// client certificate, whatever is returned on the first call (including null) is sent to the server which gets to decide
// whether or not it is acceptable. If there is a second call (which will have "Required" true and may have 
// pIssuerListInfo non-NULL) it MUST return a certificate or the handshale will fail.

SECURITY_STATUS SelectClientCertificate(PCCERT_CONTEXT & pCertContext, SecPkgContext_IssuerListInfoEx * pIssuerListInfo, bool Required)
{
   SECURITY_STATUS Status = SEC_E_CERT_UNKNOWN;

   if (Required)
   {
      // A client certificate must be returned or the handshake will fail
      if (pIssuerListInfo && pIssuerListInfo->cIssuers == 0)
         cout << "Client certificate required, issuer list is empty";
      else
      {
         cout << "Client certificate required, issuer list provided";
         Status = CertFindFromIssuerList(pCertContext, *pIssuerListInfo);
         if (!pCertContext)
            cout << " but no certificates matched";
      }
      if (!pCertContext)
         Status = CertFindClientCertificate(pCertContext); // Select any valid certificate, regardless of issuer
      // If a search for a required client certificate failed, just make one
      if (!pCertContext)
      {
         cout << ", none found, creating one";
         pCertContext = CreateCertificate(false, GetUserName() + L" at " + GetHostName());
         if (pCertContext)
            Status = S_OK;
         else
         {
            DWORD LastError = GetLastError();
            cout << endl << "**** Error 0x" << std::hex << std::setw(8) << std::setfill('0') << LastError << " in CreateCertificate" << endl 
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
      wcout << ", selected name: " << (LPCWSTR)GetCertName(pCertContext) << endl; // wcout for WCHAR* handling
   else
      cout << ", no certificate found." << endl;
   if (false && debug && pCertContext)
      ShowCertInfo(pCertContext, _T("Client certificate being returned"));
   return Status;
}

int _tmain(int argc, _TCHAR* argv[])
{
   CString HostName(GetHostName(ComputerNameDnsFullyQualified));
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
      HRESULT hr = pSSLClient->Initialize(ATL::CT2W(HostName));
		if (SUCCEEDED(hr))
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

