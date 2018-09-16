#include "stdafx.h"
#include "SSLServer.h"
#include "SSLHelper.h"
#include "CertHelper.h"

// Global value to optimize access since it is set only once
PSecurityFunctionTable CSSLServer::g_pSSPI = NULL;
// Cached server credentials (a handle to a certificate), usually these do not change 
// because the server name does not change, but occasionally they may change due to SNI
CredentialHandle CSSLServer::g_ServerCreds;
CString CSSLServer::g_ServerName = CString();

// Declare the Close functions for the handle classes using the global SSPI function table pointer

void CredentialHandle::Close() noexcept
{
	if (*this)
	{
		CSSLServer::SSPI()->FreeCredentialsHandle(&m_value);
		m_value = Invalid();
	}
}

void SecurityContextHandle::Close() noexcept
{
	if (*this)
	{
		CSSLServer::SSPI()->DeleteSecurityContext(&m_value);
		m_value = Invalid();
	}
}

// The CSSLServer class, this declares an SSL server side implementation that requires
// some means to send messages to a client (a CPassiveSock).
CSSLServer::CSSLServer(CPassiveSock * SocketStream)
	:readBufferBytes(0)
	, readPtr(readBuffer)
	, m_SocketStream(SocketStream)
	, m_LastError(0)
{
}

CSSLServer::~CSSLServer(void)
{
}

// Avoid using (or exporting) g_pSSPI directly to give us some flexibility in case we want
// to change implementation later
PSecurityFunctionTable CSSLServer::SSPI(void) { return g_pSSPI; }

// Return an ISocketStream interface to the SSL connection to anyone that needs one
ISocketStream * CSSLServer::getSocketStream(void)
{
	return m_SocketStream; // for now, return 'this' later, once we can do SSL
}

// Set up the connection, including SSL handshake, certificate selection/validation
HRESULT CSSLServer::Initialize(const void * const lpBuf, const int Len)
{
	HRESULT hr = S_OK;
	SECURITY_STATUS scRet;

	if (!g_pSSPI)
	{
		hr = InitializeClass();
		if FAILED(hr)
			return hr;
	}

	if (lpBuf && (Len > 0))
	{  // preload the IO buffer with whatever we already read
		readBufferBytes = Len;
		memcpy_s(readBuffer, sizeof(readBuffer), lpBuf, Len);
	}
	else
		readBufferBytes = 0;
	// Perform SSL handshake
	if (!SSPINegotiateLoop())
	{
		DebugMsg("Couldn't connect");
		if (IsUserAdmin())
			std::cout << "SSL handshake failed." << std::endl;
		else
			std::cout << "SSL handshake failed, perhaps because you are not running as administrator." << std::endl;
		int le = GetLastError();
		return le == 0 ? E_FAIL : HRESULT_FROM_WIN32(le);
	}

	// Find out how big the header and trailer will be:

	scRet = g_pSSPI->QueryContextAttributes(&get(m_hContext), SECPKG_ATTR_STREAM_SIZES, &Sizes);

	if (scRet != SEC_E_OK)
	{
		DebugMsg("Couldn't get Sizes");
		return E_FAIL;
	}

	return S_OK;
}

// Establish SSPI pointer
HRESULT CSSLServer::InitializeClass(void)
{
	g_pSSPI = InitSecurityInterface();

	if (g_pSSPI == NULL)
	{
		int err = ::GetLastError();
		if (err == 0)
			return E_FAIL;
		else
			return HRESULT_FROM_WIN32(err);
	}
	return S_OK;
}

// Return the last error value for this CSSLServer
int CSSLServer::GetLastError(void)
{
	if (m_LastError)
		return m_LastError;
	else
		return m_SocketStream->GetLastError();
}

// Receive an encrypted message, decrypt it, and return the resulting plaintext
int CSSLServer::Recv(void * const lpBuf, const int Len)
{
	INT err;
	INT i;
	SecBufferDesc   Message;
	SecBuffer       Buffers[4];
	SECURITY_STATUS scRet;

	//
	// Initialize security buffer structs, basically, these point to places to put encrypted data,
	// for SSL there's a header, some encrypted data, then a trailer. All three get put in the same buffer
	// (ReadBuffer) and then decrypted. So one SecBuffer points to the header, one to the data, and one to the trailer.

	//

	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;

	Buffers[0].BufferType = SECBUFFER_EMPTY;
	Buffers[1].BufferType = SECBUFFER_EMPTY;
	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;

	if (readBufferBytes == 0)
		scRet = SEC_E_INCOMPLETE_MESSAGE;
	else
	{	// There is already data in the buffer, so process it first
		DebugMsg(" ");
		DebugMsg("Using the saved %d bytes from client", readBufferBytes);
		PrintHexDump(readBufferBytes, readPtr);
		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;
		scRet = g_pSSPI->DecryptMessage(&get(m_hContext), &Message, 0, NULL);
	}

	while (scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		err = m_SocketStream->Recv((CHAR*)readPtr + readBufferBytes, sizeof(readBuffer) - readBufferBytes - ((CHAR*)readPtr - &readBuffer[0]));
		m_LastError = 0; // Means use the one from m_SocketStream
		if ((err == SOCKET_ERROR) || (err == 0))
		{
			if (WSA_IO_PENDING == m_SocketStream->GetLastError())
				DebugMsg("Recv timed out");
			else if (WSAECONNRESET == m_SocketStream->GetLastError())
				DebugMsg("Recv failed, the socket was closed by the other host");
			else
				DebugMsg("Recv failed: %ld", m_SocketStream->GetLastError());
			return SOCKET_ERROR;
		}
		DebugMsg(" ");
		DebugMsg("Received %d (request) bytes from client", err);
		PrintHexDump(err, (CHAR*)readPtr + readBufferBytes);
		readBufferBytes += err;

		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		scRet = g_pSSPI->DecryptMessage(&get(m_hContext), &Message, 0, NULL);
	}


	if (scRet == SEC_E_OK)
		DebugMsg("Decrypted message from client.");
	else
	{
		DebugMsg("Couldn't decrypt, error %lx", scRet);
		m_LastError = scRet;
		return SOCKET_ERROR;
	}

	// Locate the data buffer because the decrypted data is placed there. It's almost certainly
	// the second buffer (index 1) and we start there, but search all but the first just in case...
	PSecBuffer pDataBuffer(NULL);

	for (i = 1; i < 4; i++)
	{
		if (Buffers[i].BufferType == SECBUFFER_DATA)
		{
			pDataBuffer = &Buffers[i];
			break;
		}
	}

	if (!pDataBuffer)
	{
		DebugMsg("No data returned");
		m_LastError = WSASYSCALLFAILURE;
		return SOCKET_ERROR;
	}
	DebugMsg(" ");
	DebugMsg("Decrypted message has %d bytes", pDataBuffer->cbBuffer);
	PrintHexDump(pDataBuffer->cbBuffer, pDataBuffer->pvBuffer);

	// Move the data to the output stream

	if (Len >= int(pDataBuffer->cbBuffer))
		memcpy_s(lpBuf, Len, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
	else
	{	// More bytes were decoded than the caller requested, so return an error
		m_LastError = WSAEMSGSIZE;
		return SOCKET_ERROR;
	}

	// See if there was any extra data read beyond what was needed for the message we are handling
	// TCP can sometime merge multiple messages into a single one, if there is, it will amost 
	// certainly be in the fourth buffer (index 3), but search all but the first, just in case.
	PSecBuffer pExtraDataBuffer(NULL);

	for (i = 1; i < 4; i++)
	{
		if (Buffers[i].BufferType == SECBUFFER_EXTRA)
		{
			pExtraDataBuffer = &Buffers[i];
			break;
		}
	}

	if (pExtraDataBuffer)
	{	// More data was read than is needed, this happens sometimes with TCP
		DebugMsg(" ");
		DebugMsg("Some extra ciphertext was read (%d bytes)", pExtraDataBuffer->cbBuffer);
		// Remember where the data is for next time
		readBufferBytes = pExtraDataBuffer->cbBuffer;
		readPtr = pExtraDataBuffer->pvBuffer;
	}
	else
	{
		DebugMsg("No extra ciphertext was read");
		readBufferBytes = 0;
		readPtr = readBuffer;
	}

	return pDataBuffer->cbBuffer;
}

// Send an encrypted message containing an encrypted version of 
// whatever plaintext data the caller provides
int CSSLServer::Send(const void * const lpBuf, const int Len)
{
	if (!lpBuf || Len > MaxMsgSize)
		return SOCKET_ERROR;

	INT err;

	SecBufferDesc   Message;
	SecBuffer       Buffers[4];
	SECURITY_STATUS scRet;

	//
	// Initialize security buffer structs
	//

	Message.ulVersion = SECBUFFER_VERSION;
	Message.cBuffers = 4;
	Message.pBuffers = Buffers;

	Buffers[0].BufferType = SECBUFFER_EMPTY;
	Buffers[1].BufferType = SECBUFFER_EMPTY;
	Buffers[2].BufferType = SECBUFFER_EMPTY;
	Buffers[3].BufferType = SECBUFFER_EMPTY;

	// Put the message in the right place in the buffer
	memcpy_s(writeBuffer + Sizes.cbHeader, sizeof(writeBuffer) - Sizes.cbHeader - Sizes.cbTrailer, lpBuf, Len);

	//
	// Line up the buffers so that the header, trailer and content will be
	// all positioned in the right place to be sent across the TCP connection as one message.
	//

	Buffers[0].pvBuffer = writeBuffer;
	Buffers[0].cbBuffer = Sizes.cbHeader;
	Buffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	Buffers[1].pvBuffer = writeBuffer + Sizes.cbHeader;
	Buffers[1].cbBuffer = Len;
	Buffers[1].BufferType = SECBUFFER_DATA;

	Buffers[2].pvBuffer = writeBuffer + Sizes.cbHeader + Len;
	Buffers[2].cbBuffer = Sizes.cbTrailer;
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	Buffers[3].BufferType = SECBUFFER_EMPTY;

	scRet = g_pSSPI->EncryptMessage(&get(m_hContext), 0, &Message, 0);

	DebugMsg(" ");
	DebugMsg("Plaintext message has %d bytes", Len);
	PrintHexDump(Len, lpBuf);

	if (FAILED(scRet))
	{
		DebugMsg("EncryptMessage failed with %#x", scRet);
		m_LastError = scRet;
		return SOCKET_ERROR;
	}

	err = m_SocketStream->Send(writeBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	m_LastError = 0;

	DebugMsg("Send %d encrypted bytes to client", Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	PrintHexDump(Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, writeBuffer);
	if (err == SOCKET_ERROR)
	{
		DebugMsg("Send failed: %ld", m_SocketStream->GetLastError());
		return SOCKET_ERROR;
	}
	return Len;
}

// Negotiate a connection with the client, sending and receiving messages until the
// negotiation succeeds or fails
bool CSSLServer::SSPINegotiateLoop(void)
{
	TimeStamp            tsExpiry;
	SECURITY_STATUS      scRet;
	SecBufferDesc        InBuffer;
	SecBufferDesc        OutBuffer;
	SecBuffer            InBuffers[2];
	SecBuffer            OutBuffers[1];
	DWORD                err = 0;
	DWORD                dwSSPIOutFlags = 0;
	bool				 ContextHandleValid = (bool)m_hContext;

	DWORD dwSSPIFlags =
		ASC_REQ_SEQUENCE_DETECT |
		ASC_REQ_REPLAY_DETECT |
		ASC_REQ_CONFIDENTIALITY |
		ASC_REQ_EXTENDED_ERROR |
		ASC_REQ_ALLOCATE_MEMORY |
		ASC_REQ_STREAM;

	if (ClientCertAcceptable) // If the caller wants a client certificate, request one
	{
		DebugMsg("Client certificate will be required.");
		dwSSPIFlags |= ASC_REQ_MUTUAL_AUTH;
	}

	//
	//  set OutBuffer for InitializeSecurityContext call
	//

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	DebugMsg("Started SSPINegotiateLoop with %d bytes already received from client.", readBufferBytes);

	scRet = SEC_E_INCOMPLETE_MESSAGE;

	// Main loop, keep going around this until the handshake is completed or fails
	while (scRet == SEC_I_CONTINUE_NEEDED || scRet == SEC_E_INCOMPLETE_MESSAGE || scRet == SEC_I_INCOMPLETE_CREDENTIALS)
	{
		if (readBufferBytes == 0 || scRet == SEC_E_INCOMPLETE_MESSAGE)
		{	// Read some more bytes if available, we may read more than is needed for this phase of handshake 
			err = m_SocketStream->Recv(readBuffer + readBufferBytes, sizeof(readBuffer) - readBufferBytes);
			m_LastError = 0;
			if (err == SOCKET_ERROR || err == 0)
			{
				if (WSA_IO_PENDING == m_SocketStream->GetLastError())
					DebugMsg("Recv timed out");
				else if (WSAECONNRESET == m_SocketStream->GetLastError())
					DebugMsg("Recv failed, the socket was closed by the other host");
				else
					DebugMsg("Recv failed: %d", m_SocketStream->GetLastError());
				return false;
			}
			else
			{
				readBufferBytes += err;
				DebugMsg(" ");
				if (err == readBufferBytes)
					DebugMsg("Received %d handshake bytes from client", err);
				else
					DebugMsg("Received %d handshake bytes from client, total is now %d ", err, readBufferBytes);
				CSSLHelper SSLHelper((const byte*)readBuffer, readBufferBytes);
				SSLHelper.TraceHandshake();
				if (SSLHelper.IsClientInitialize())
				{  // Figure out what certificate we might want to use, either using SNI or the local host name
					CString serverName = SSLHelper.GetSNI();
					if ((!g_ServerCreds) // No certificate handle stored
						|| (serverName.Compare(g_ServerName) != 0)) // Requested names are different
					{  // 
						if (g_ServerCreds) // Certificate handle stored
							g_pSSPI->FreeCredentialsHandle(&get(g_ServerCreds));
						if (serverName.IsEmpty()) // There was no hostname supplied by SNI
							serverName = GetHostName();
						PCCERT_CONTEXT pCertContext = NULL;
						SECURITY_STATUS status = SEC_E_INTERNAL_ERROR;
						if (SelectServerCert)
						{
							status = SelectServerCert(pCertContext, (LPCTSTR)serverName);
							if (FAILED(status))
							{
								DebugMsg("SelectServerCert returned an error = 0x%08x", status);
								scRet = SEC_E_INTERNAL_ERROR;
								break;
							}
						}
						else
							status = CertFindServerCertificateByName(pCertContext, (LPCTSTR)serverName); // Add "true" to look in user store, "false", or nothing looks in machine store
						g_ServerName = (SUCCEEDED(status)) ? serverName : CString();
						if (SUCCEEDED(status))
						{
							status = CreateCredentialsFromCertificate(set(g_ServerCreds), pCertContext);
						}
						if (FAILED(status))
						{
							DebugMsg("Failed handling server initialization, error = 0x%08x", status);
							scRet = SEC_E_INTERNAL_ERROR;
							break;
						}
					}
				}
			}
		}

		//
		// InBuffers[1] is used for storing extra data that SSPI/SCHANNEL doesn't process on this run around the loop.
		//
		// Set up the input buffers. Buffer 0 is used to pass in data
		// received from the server. Schannel will consume some or all
		// of this. Leftover data (if any) will be placed in buffer 1 and
		// given a buffer type of SECBUFFER_EXTRA.
		//

		InBuffers[0].pvBuffer = readBuffer;
		InBuffers[0].cbBuffer = readBufferBytes;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer = NULL;
		InBuffers[1].cbBuffer = 0;
		InBuffers[1].BufferType = SECBUFFER_EMPTY;

		InBuffer.cBuffers = 2;
		InBuffer.pBuffers = InBuffers;
		InBuffer.ulVersion = SECBUFFER_VERSION;

		//
		// Set up the output buffers. These are initialized to NULL
		// so as to make it less likely we'll attempt to free random
		// garbage later.
		//

		OutBuffers[0].pvBuffer = NULL;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = 0;

		scRet = g_pSSPI->AcceptSecurityContext(
			&get(g_ServerCreds),								// Which certificate to use, already established
			ContextHandleValid ? &get(m_hContext) : NULL,	// The context handle if we have one, ask to make one if this is first call
			&InBuffer,										// Input buffer list
			dwSSPIFlags,									// What we require of the connection
			0,													// Data representation, not used 
			ContextHandleValid ? NULL : set(m_hContext),	// If we don't yet have a context handle, it is returned here
			&OutBuffer,										// [out] The output buffer, for messages to be sent to the other end
			&dwSSPIOutFlags,								// [out] The flags associated with the negotiated connection
			&tsExpiry);										// [out] Receives context expiration time

		ContextHandleValid = true;

		if (scRet == SEC_E_OK || scRet == SEC_I_CONTINUE_NEEDED
			|| (FAILED(scRet) && (0 != (dwSSPIOutFlags & ASC_RET_EXTENDED_ERROR))))
		{
			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
			{
				// Send response to client if there is one
				err = m_SocketStream->CPassiveSock::Send(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
				m_LastError = 0;
				if (err == SOCKET_ERROR || err == 0)
				{
					DebugMsg("Send handshake to client failed: %d", m_SocketStream->GetLastError());
					g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
					return false;
				}
				else
				{
					DebugMsg(" ");
					DebugMsg("Send %d handshake bytes to client", OutBuffers[0].cbBuffer);
					PrintHexDump(OutBuffers[0].cbBuffer, OutBuffers[0].pvBuffer);
				}

				g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer = NULL;
			}
		}

		// At this point, we've read and checked a message (giving scRet) and maybe sent a response (giving err)
	  // as far as the client is concerned, the SSL handshake may be done, but we still have checks to make.

		if (scRet == SEC_E_OK)
		{	// The termination case, the handshake worked and is completed, this could as easily be outside the loop

		 // Ensure a client certificate is checked if one was requested, if none was provided we'd already have failed
			if (ClientCertAcceptable)
			{
				PCERT_CONTEXT pCertContext = NULL;
				HRESULT hr = g_pSSPI->QueryContextAttributes(&get(m_hContext), SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCertContext);

				if (FAILED(hr))
					DebugMsg("Couldn't get client certificate, hr=%#x", hr);
				else
				{
					DebugMsg("Client Certificate returned");
					if (false && debug && pCertContext)
						ShowCertInfo(pCertContext, _T("Server Received Client Certificate"));
					// All looking good, now see if there's a client certificate, and if it is valid
					bool acceptable = ClientCertAcceptable(pCertContext, S_OK == CertTrusted(pCertContext, true));
					CertFreeCertificateContext(pCertContext);
					if (acceptable)
						DebugMsg("Client certificate was acceptable");
					else
					{
						DebugMsg("Client certificate was unacceptable");
						return false;
					}
				}
			}

			// Now deal with the possibility that there were some data bytes tacked on to the end of the handshake
			if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				readPtr = readBuffer + (readBufferBytes - InBuffers[1].cbBuffer);
				readBufferBytes = InBuffers[1].cbBuffer;
				DebugMsg("Handshake worked, but received %d extra bytes", readBufferBytes);
			}
			else
			{
				readBufferBytes = 0;
				readPtr = readBuffer;
				DebugMsg("Handshake worked, no extra bytes received");
			}
			m_LastError = 0;
			return true; // The normal exit
		}
		else if (scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			DebugMsg("AcceptSecurityContext got a partial message and is requesting more be read");
		}
		else if (scRet == SEC_E_INCOMPLETE_CREDENTIALS)
		{
			DebugMsg("AcceptSecurityContext got SEC_E_INCOMPLETE_CREDENTIALS, it shouldn't but we'll treat it like a partial message");
		}
		else if (FAILED(scRet))
		{
			if (scRet == SEC_E_INVALID_TOKEN)
				DebugMsg("AcceptSecurityContext detected an invalid token, maybe the client rejected our certificate");
			else
				DebugMsg("AcceptSecurityContext Failed with error code %lx", scRet);
			m_LastError = scRet;
			return false;
		}
		else
		{  // We won't be appending to the message data already in the buffer, so store a reference to any extra data in case it is useful
			if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				readPtr = readBuffer + (readBufferBytes - InBuffers[1].cbBuffer);
				readBufferBytes = InBuffers[1].cbBuffer;
				DebugMsg("Handshake working so far but received %d extra bytes we can't handle", readBufferBytes);
				m_LastError = WSASYSCALLFAILURE;
				return false;
			}
			else
			{
				readPtr = readBuffer;
				readBufferBytes = 0; // prepare for next receive
				DebugMsg("Handshake working so far, more packets required");
			}
		}
	} // while loop

	// Somthing is wrong, we exited the loop abnormally
	DebugMsg("Unexpected scRet value %lx", scRet);
	m_LastError = scRet;
	return false;
}

// In theory a connection may switch in and out of SSL mode.
// This stops SSL, but it has not been tested
HRESULT CSSLServer::Disconnect(void)
{
	DWORD           dwType;
	PBYTE           pbMessage;
	DWORD           cbMessage;
	DWORD           cbData;

	SecBufferDesc   OutBuffer;
	SecBuffer       OutBuffers[1];
	DWORD           dwSSPIFlags;
	DWORD           dwSSPIOutFlags;
	TimeStamp       tsExpiry;
	DWORD           Status;

	//
	// Notify schannel that we are about to close the connection.
	//

	dwType = SCHANNEL_SHUTDOWN;

	OutBuffers[0].pvBuffer = &dwType;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = sizeof(dwType);

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->ApplyControlToken(&get(m_hContext), &OutBuffer);

	if (FAILED(Status))
	{
		DebugMsg("**** Error 0x%x returned by ApplyControlToken", Status);
		return Status;
	}

	//
	// Build an SSL close notify message.
	//

	dwSSPIFlags =
		ASC_REQ_SEQUENCE_DETECT |
		ASC_REQ_REPLAY_DETECT |
		ASC_REQ_CONFIDENTIALITY |
		ASC_REQ_EXTENDED_ERROR |
		ASC_REQ_ALLOCATE_MEMORY |
		ASC_REQ_STREAM;

	OutBuffers[0].pvBuffer = NULL;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->AcceptSecurityContext(
		&get(g_ServerCreds),			// Which certificate to use, already established
		&get(m_hContext),				// The context handle
		NULL,							// Input buffer list
		dwSSPIFlags,				// What we require of the connection
		0,								// Data representation, not used 
		NULL,							// Returned context handle, not used, because we already have one
		&OutBuffer,					// [out] The output buffer, for messages to be sent to the other end
		&dwSSPIOutFlags,			// [out] The flags associated with the negotiated connection
		&tsExpiry);					// [out] Receives context expiration time

	if (FAILED(Status))
	{
		DebugMsg("**** Error 0x%x returned by AcceptSecurityContext", Status);
		return Status;
	}

	pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
	cbMessage = OutBuffers[0].cbBuffer;


	//
	// Send the close notify message to the client.
	//

	if (pbMessage != NULL && cbMessage != 0)
	{
		cbData = m_SocketStream->Send(pbMessage, cbMessage);
		if (cbData == SOCKET_ERROR || cbData == 0)
		{
			Status = m_SocketStream->GetLastError();
			DebugMsg("**** Error %d sending close notify", Status);
			return HRESULT_FROM_WIN32(Status);
		}

		DebugMsg(" ");
		DebugMsg("%d bytes of data sent to notify SCHANNEL_SHUTDOWN", cbData);
		PrintHexDump(cbData, pbMessage);
	}
	m_SocketStream->Disconnect();
	return S_OK;
}
// Create credentials (a handle to a credential context) from a certificate
SECURITY_STATUS CSSLServer::CreateCredentialsFromCertificate(PCredHandle phCreds, PCCERT_CONTEXT pCertContext)
{
	DebugMsg("CreateCredentialsFromCertificate 0x%.8x '%S'.", pCertContext, GetCertName(pCertContext));

	// Build Schannel credential structure.
	SCHANNEL_CRED   SchannelCred = { 0 };
	SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
	SchannelCred.cCreds = 1;
	SchannelCred.paCred = &pCertContext;
	SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_SERVER;
	SchannelCred.dwFlags = SCH_USE_STRONG_CRYPTO;

	SECURITY_STATUS Status;
	TimeStamp       tsExpiry;
	// Get a handle to the SSPI credential
	Status = g_pSSPI->AcquireCredentialsHandle(
		NULL,                   // Name of principal
		UNISP_NAME,           // Name of package
		SECPKG_CRED_INBOUND,    // Flags indicating use
		NULL,                   // Pointer to logon ID
		&SchannelCred,          // Package specific data
		NULL,                   // Pointer to GetKey() func
		NULL,                   // Value to pass to GetKey()
		phCreds,                // (out) Cred Handle
		&tsExpiry);             // (out) Lifetime (optional)

	if (Status != SEC_E_OK)
	{
		DWORD dw = GetLastError();
		if (Status == SEC_E_UNKNOWN_CREDENTIALS)
			DebugMsg("**** Error: 'Unknown Credentials' returned by AcquireCredentialsHandle. Be sure app has administrator rights. LastError=%d", dw);
		else
			DebugMsg("**** Error 0x%x returned by AcquireCredentialsHandle. LastError=%d.", Status, dw);
		return Status;
	}

	return SEC_E_OK;
}

// End of CSSLServer declarations