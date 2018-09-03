#include "stdafx.h"
#include "Transport.h"

#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#define new DEBUG_NEW
#endif

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

CTransport::CTransport(SOCKET s, CListener * Listener) : // constructor requires a socket already assigned
	IsConnected(false)
	, m_Listener(Listener)
	, SSLServer(NULL)
{
	PassiveSock = new CPassiveSock(s, Listener->m_StopEvent);
	SocketStream = PassiveSock;
	PassiveSock->SetTimeoutSeconds(60);
	SSLServer = new CSSLServer(PassiveSock);
	SSLServer->SelectServerCert = Listener->SelectServerCert;
	SSLServer->ClientCertAcceptable = Listener->ClientCertAcceptable;
	HRESULT hr = SSLServer->Initialize();
	if SUCCEEDED(hr)
	{
		SocketStream = SSLServer;
		IsConnected = true;
	}
	else
	{
		int err = SSLServer->GetLastError();
		delete SSLServer;
		SSLServer = NULL;
		if (hr == SEC_E_INVALID_TOKEN)
			m_Listener->LogWarning(_T("SSL token invalid, perhaps the client rejected our certificate"));
		else if (hr == CRYPT_E_NOT_FOUND)
			m_Listener->LogWarning(_T("A usable SSL certificate could not be found"));
		else if (hr == E_ACCESSDENIED)
			m_Listener->LogWarning(_T("Could not access certificate store, is this program running with administrative privileges?"));
		else if (hr == SEC_E_UNKNOWN_CREDENTIALS)
			m_Listener->LogWarning(_T("Credentials unknown, is this program running with administrative privileges?"));
		else if (hr == SEC_E_CERT_UNKNOWN)
			m_Listener->LogWarning(_T("The returned client certificate was unacceptable"));
		else
		{
			CString s;
			s.Format(_T("SSL could not be used, hr =0x%lx, lasterror=0x%lx"), hr, err);
			m_Listener->LogWarning(s);
		}
	}
}

CTransport::~CTransport()
{
	delete SSLServer;
	delete PassiveSock;
}

int CTransport::Recv(void * const lpBuf, const int MaxLen)
{
	if (!IsConnected) return -1;
	int Len = SocketStream->Recv(lpBuf, MaxLen);
	return Len;
}

int CTransport::Send(const void * const lpBuf, const int RequestedLen)
{
	if (!IsConnected) return -1;
	return PassiveSock->Send(lpBuf, RequestedLen);
}