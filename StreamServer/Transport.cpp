#include "pch.h"
#include "framework.h"

#include "Transport.h"
#include "SSLServer.h"
#include "Listener.h"
#include "Utilities.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

// A CTransport conbines a CPassiveSock to do the actual data transmission with an SSLServer which
// adds SSL capability to the data transmission object. It is passed a reference to a CListener object
// which acts as a class factory for incoming socket connections.
// Once a CTransport instance is created it will be passed to a worker thread which will use it to 
// run the user provided code originally passed to the CSSLServer the client actually declared
// (a reference to that code is stored in the Listener). 

CTransport::CTransport(SOCKET s, CListener * Listener) // constructor requires a socket already assigned
	: m_Listener(Listener)
{
	Listener ->IncrementTransportCount();
	PassiveSock = std::make_unique<CPassiveSock>(s, Listener->m_StopEvent);
	PassiveSock->SetSendTimeoutSeconds(10);
	PassiveSock->SetRecvTimeoutSeconds(60);
	SSLServer = std::make_unique<CSSLServer>(PassiveSock.get());
	SSLServer->SelectServerCert = Listener->SelectServerCert;
	SSLServer->ClientCertAcceptable = Listener->ClientCertAcceptable;
	HRESULT hr = SSLServer->Initialize();
	if SUCCEEDED(hr)
	{
		SocketStream = SSLServer.get(); // Redirect the ISocketSteam interface to the code in CSSLServer 
		IsConnected = true;
	}
	else
	{
		int err = SSLServer->GetLastError();
		SSLServer = nullptr;
		if (hr == SEC_E_INVALID_TOKEN)
			m_Listener->LogWarning(L"SSL token invalid, perhaps the client rejected our certificate");
		else if (hr == CRYPT_E_NOT_FOUND)
			m_Listener->LogWarning(L"A usable SSL certificate could not be found");
		else if (hr == E_ACCESSDENIED)
			m_Listener->LogWarning(L"Could not access certificate store, is this program running with administrative privileges?");
		else if (hr == SEC_E_UNKNOWN_CREDENTIALS)
			m_Listener->LogWarning(L"Credentials unknown, is this program running with administrative privileges?");
		else if (hr == SEC_E_CERT_UNKNOWN)
			m_Listener->LogWarning(L"The returned client certificate was unacceptable");
		else
		{
			std::wstring m = string_format(L"SSL could not be used, hr =0x%lx, lasterror=0x%lx", hr, err);
			m_Listener->LogWarning(m.c_str());
		}
	}
}

CTransport::~CTransport()
{
	m_Listener->IncrementTransportCount(-1);
}