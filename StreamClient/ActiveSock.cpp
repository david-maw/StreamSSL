#include "pch.h"
#include "framework.h"

#include "ActiveSock.h"
#include "Utilities.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

CActiveSock::CActiveSock(HANDLE StopEvent)
  : CBaseSock(StopEvent)
{
}

CActiveSock::~CActiveSock()
{
	if (ActualSocket != INVALID_SOCKET)
		Disconnect();
}

bool CActiveSock::Connect(LPCTSTR HostName, USHORT PortNumber)
{
	int iResult;
	BOOL bSuccess;
	SOCKADDR_STORAGE LocalAddr = { 0 };
	SOCKADDR_STORAGE RemoteAddr = { 0 };
	DWORD dwLocalAddr = sizeof(LocalAddr);
	DWORD dwRemoteAddr = sizeof(RemoteAddr);
	WCHAR PortName[10] = { 0 };
	timeval Timeout = { 0 };

	Timeout.tv_sec = GetSendTimeoutSeconds();

	_itot_s(PortNumber, PortName, _countof(PortName), 10);

	ActualSocket = socket(AF_INET, SOCK_STREAM, 0);
	if (ActualSocket == INVALID_SOCKET) {
		DebugMsg("socket failed with error: %d\n", WSAGetLastError());
		return false;
	}

	// Note that WSAConnectByName requires Vista or Server 2008
	bSuccess = WSAConnectByName(ActualSocket, const_cast<LPWSTR>(HostName),
		PortName, &dwLocalAddr,
		(SOCKADDR*)&LocalAddr,
		&dwRemoteAddr,
		(SOCKADDR*)&RemoteAddr,
		&Timeout,
		nullptr);

	if (!bSuccess) {
		LastError = WSAGetLastError();
		DebugMsg("**** WsaConnectByName Error %d connecting to \"%S\" (%S)",
			LastError,
			HostName,
			PortName);
		CloseAndInvalidateSocket();
		return false;
	}
	iResult = setsockopt(ActualSocket, SOL_SOCKET,
		0x7010 /*SO_UPDATE_CONNECT_CONTEXT*/, nullptr, 0);
	if (iResult == SOCKET_ERROR) {
		LastError = WSAGetLastError();
		DebugMsg("setsockopt for SO_UPDATE_CONNECT_CONTEXT failed with error: %d", LastError);
		CloseAndInvalidateSocket();
		return false;
	}
	//// At this point we have a connection, so set up keepalives so we can detect if the host disconnects
	//// This code is commented out because it does not seen to be helpful
	//BOOL so_keepalive = TRUE;
	//int iResult = setsockopt(ActualSocket, SOL_SOCKET, SO_KEEPALIVE, (const char *)&so_keepalive, sizeof(so_keepalive));
	//	if (iResult == SOCKET_ERROR){
	//		LastError = WSAGetLastError();
	//		wprintf(L"setsockopt for SO_KEEPALIVE failed with error: %d\n",
	//			LastError);
	//		CloseAndInvalidateSocket();
	//		return false;
	//	}

	//// Now set keepalive timings

	//DWORD dwBytes = 0;
	//tcp_keepalive sKA_Settings = {0}, sReturned = {0} ;

	//sKA_Settings.onoff = 1 ;
	//sKA_Settings.keepalivetime = 1000; // Keep Alive in 1 sec.
	//sKA_Settings.keepaliveinterval = 1000 ; // Resend if No-Reply
	//if (WSAIoctl(ActualSocket, SIO_KEEPALIVE_VALS, &sKA_Settings,
	//	sizeof(sKA_Settings), &sReturned, sizeof(sReturned), &dwBytes,
	//	NULL, NULL) != 0)
	//{
	//	LastError = WSAGetLastError() ;
	//	wprintf(L"WSAIoctl to set keepalive failed with error: %d\n", LastError);
	//	CloseAndInvalidateSocket();
	//	return false;
	//}

	return SUCCEEDED(Setup());
}