#include "stdafx.h"
#include "SSLServer.h"
#include "SSLHelper.h"
#include "CertHelper.h"
#include "ServerCert.h"

// Global value to optimize access since it is set only once
PSecurityFunctionTable CSSLServer::g_pSSPI = NULL;

// Declare the Close functions for the handle classes using the global SSPI function table pointer

void CredentialTraits::Close(Type value)
{
	CSSLServer::SSPI()->FreeCredentialsHandle(&value);
}

void SecurityContextTraits::Close(Type value)
{
	CSSLServer::SSPI()->DeleteSecurityContext(&value);
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
HRESULT CSSLServer::Initialize(const void * const lpBuf, const size_t Len)
{
	HRESULT hr = S_OK;
	SECURITY_STATUS scRet;

	if (!g_pSSPI)
	{
		hr = InitializeClass();
		if FAILED(hr)
			return hr;
	}
	if (!g_pSSPI)
		return E_POINTER;

	if (lpBuf && (Len > 0))
	{  // preload the IO buffer with whatever we already read
		readBufferBytes = static_cast<decltype(readBufferBytes)>(Len);
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
	scRet = g_pSSPI->QueryContextAttributes(m_hContext.getunsaferef(), SECPKG_ATTR_STREAM_SIZES, &Sizes);

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

int CSSLServer::Recv(void* const lpBuf, const size_t Len)
{
	if (m_encrypting)
		return RecvEncrypted(lpBuf, Len);
	else
	{
		// Not currently encrypting, just receive from the socket
		DebugMsg("Recv called and we are not encrypting");
		if (readBufferBytes > 0)
		{	// There is already data in the buffer, so process it first
			DebugMsg("Using the saved %d bytes from client, which may well be encrypted", readBufferBytes);
			PrintHexDump(readBufferBytes, readPtr);
			if (Len >= int(readBufferBytes))
			{
				memcpy_s(lpBuf, Len, readPtr, readBufferBytes);
				int i = readBufferBytes;
				readBufferBytes = 0;
				return i;
			}
			else
			{	// More bytes were decoded than the caller requested, so return an error
				m_LastError = WSAEMSGSIZE;
				return SOCKET_ERROR;
			}
		}
		else
		{
			int err = m_SocketStream->Recv(lpBuf, Len);
			m_LastError = 0; // Means use the one from m_SocketStream
			if ((err == SOCKET_ERROR) || (err == 0))
			{
				if (ERROR_TIMEOUT == m_SocketStream->GetLastError())
					DebugMsg("Recv timed out");
				else if (WSA_IO_PENDING == m_SocketStream->GetLastError())
					DebugMsg("Recv Overlapped operations will complete later");
				else if (WSAECONNRESET == m_SocketStream->GetLastError())
					DebugMsg("Recv failed, the socket was closed by the other host");
				else
					DebugMsg("Recv failed: %ld", m_SocketStream->GetLastError());
				return SOCKET_ERROR;
			}
			else
			{
				DebugMsg("Received %d unencrypted bytes from client", err);
				PrintHexDump(err, lpBuf);
				return err; // normal case, returns received message length
			}
		}
	}
}

// Receive an encrypted message, decrypt it, and return the resulting plaintext
int CSSLServer::RecvEncrypted(void * const lpBuf, const size_t Len)
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
		scRet = g_pSSPI->DecryptMessage(m_hContext.getunsaferef(), &Message, 0, NULL);
		readBufferBytes = 0; // We have consumed them
	}

	while (scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		err = m_SocketStream->Recv((CHAR*)readPtr + readBufferBytes, static_cast<int>(sizeof(readBuffer) - readBufferBytes - ((CHAR*)readPtr - &readBuffer[0])));
		m_LastError = 0; // Means use the one from m_SocketStream
		if ((err == SOCKET_ERROR) || (err == 0))
		{
			if (ERROR_TIMEOUT == m_SocketStream->GetLastError())
				DebugMsg("Recv timed out");
			else if (WSA_IO_PENDING == m_SocketStream->GetLastError())
				DebugMsg("Recv Overlapped operations will complete later");
			else if (WSAECONNRESET == m_SocketStream->GetLastError())
				DebugMsg("Recv failed, the socket was closed by the other host");
			else
				DebugMsg("Recv failed: %ld", m_SocketStream->GetLastError());
			return SOCKET_ERROR;
		}
		DebugMsg(" ");
		DebugMsg("Received %d encrypted bytes from client", err);
		PrintHexDump(err, (CHAR*)readPtr + readBufferBytes);
		readBufferBytes += err;

		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;


		// This is a horrible kludge because apparently DecryptMessage isn't smart enough to recognize a
		// shutdown message with other data concatenated
		const int headerLen = 5, shutdownLen = 26;
		if (((CHAR*)readPtr)[0] == 21 // Alert message type
			&& readBufferBytes > (shutdownLen + headerLen) // Could be a shutdown message followed by something else
			&& ((CHAR*)readPtr)[3] == 0 && ((CHAR*)readPtr)[4] == shutdownLen // the first message is the correct length for a shutdown message
			&& ((CHAR*)readPtr)[5] == 0 // it is a "close notify" (aka shutdown) message
			)
		{
			DebugMsg("Looks like a concatenated shutdown message and something else");
			PrintHexDump(err, readPtr, true);
			Buffers[0].cbBuffer = shutdownLen + headerLen;
			scRet = g_pSSPI->DecryptMessage(m_hContext.getunsaferef(), &Message, 0, NULL);
			if (scRet == SEC_I_CONTEXT_EXPIRED)
			{
				Buffers[1].pvBuffer = (CHAR*)readPtr + shutdownLen + headerLen;
				Buffers[1].cbBuffer = readBufferBytes - shutdownLen - headerLen;
				Buffers[1].BufferType = SECBUFFER_EXTRA;
			}
		}
		else // The normal case
			scRet = g_pSSPI->DecryptMessage(m_hContext.getunsaferef(), &Message, 0, NULL);
	}

	PSecBuffer pDataBuffer(NULL); // Points to databuffer if there is one

	if (scRet == SEC_E_OK)
	{
		DebugMsg("Decrypted message from client.");
		// Locate the data buffer because the decrypted data is placed there. It's almost certainly
		// the second buffer (index 1) and we start there, but search all but the first just in case...

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
	}
	else if (scRet == SEC_I_CONTEXT_EXPIRED)
	{
		DebugMsg("Notified that SSL disabled");
		m_LastError = scRet;
		m_encrypting = false;
	}
	else
	{
		DebugMsg("Couldn't decrypt, error %lx", scRet);
		
		readBufferBytes = 0; // Assume they have all been consumed
		return SOCKET_ERROR;
	}

	// See if there was any extra data read beyond what was needed for the message we are handling
	// TCP can sometime merge multiple messages into a single one, if there is, it will almost 
	// certainly be in the fourth buffer (index 3), but search all but the first, just in case.
	// This does not work with a shutdown message - if it is concatenated with a following plaintext
	// the decryption just fails with a "cannot decrypt" error, which is why it has special handling above.
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
		DebugMsg("Some extra data was read (%d bytes)", pExtraDataBuffer->cbBuffer);
		// Remember where the data is for next time
		readBufferBytes = pExtraDataBuffer->cbBuffer;
		readPtr = pExtraDataBuffer->pvBuffer;
	}
	else
	{
		DebugMsg("No extra data was read");
		readBufferBytes = 0;
		readPtr = readBuffer;
	}

	return (pDataBuffer) ? pDataBuffer->cbBuffer : 0;
}

// Send an encrypted message containing an encrypted version of 
// whatever plaintext data the caller provides
int CSSLServer::Send(const void * const lpBuf, const size_t Len)
{
	if (!lpBuf || Len > MaxMsgSize)
		return SOCKET_ERROR;

	if (!m_encrypting)
	{
		DebugMsg("Send can only be called when encrypting");
		m_LastError = ERROR_FILE_NOT_ENCRYPTED;
		return SOCKET_ERROR;
	}

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
	Buffers[1].cbBuffer = static_cast<decltype(Buffers[1].cbBuffer)>(Len);
	Buffers[1].BufferType = SECBUFFER_DATA;

	Buffers[2].pvBuffer = writeBuffer + Sizes.cbHeader + Len;
	Buffers[2].cbBuffer = Sizes.cbTrailer;
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	Buffers[3].BufferType = SECBUFFER_EMPTY;

	scRet = g_pSSPI->EncryptMessage(m_hContext.getunsaferef(), 0, &Message, 0);

	DebugMsg(" ");
	DebugMsg("Plaintext message has %d bytes", Len);
	PrintHexDump(static_cast<DWORD>(Len), lpBuf);

	if (FAILED(scRet))
	{
		DebugMsg("EncryptMessage failed with %#x", scRet);
		m_LastError = scRet;
		return SOCKET_ERROR;
	}

	err = m_SocketStream->Send(writeBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	m_LastError = 0;

	DebugMsg("Send %d encrypted bytes to client", Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	PrintHexDump(static_cast<DWORD>(Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer), writeBuffer);
	if (err == SOCKET_ERROR)
	{
		DebugMsg("Send failed: %ld", m_SocketStream->GetLastError());
		return SOCKET_ERROR;
	}
	return static_cast<int>(Len);
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

	if (m_encrypting)
	{
		DebugMsg("SSPINegotiateLoop called twice");
		return false;
	}

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
				if (ERROR_TIMEOUT == m_SocketStream->GetLastError())
					DebugMsg("Recv timed out");
				else if (WSA_IO_PENDING == m_SocketStream->GetLastError())
					DebugMsg("Recv Overlapped operations will complete later");
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
					std::wstring serverName = SSLHelper.GetSNI();
					scRet = GetCredHandleFor(serverName, SelectServerCert, &hServerCreds);
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
			&hServerCreds,									// Which certificate to use, already established
			ContextHandleValid ? m_hContext.getunsaferef() : NULL, // The context handle if we have one, ask to make one if this is first call
			&InBuffer,										// Input buffer list
			dwSSPIFlags,									// What we require of the connection
			0,													// Data representation, not used 
			ContextHandleValid ? NULL : m_hContext.set(),	// If we don't yet have a context handle, it is returned here
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
				HRESULT hr = g_pSSPI->QueryContextAttributes(m_hContext.getunsaferef(), SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCertContext);

				if (FAILED(hr))
					DebugMsg("Couldn't get client certificate, hr=%#x", hr);
				else
				{
					DebugMsg("Client Certificate returned");
					if (false && debug && pCertContext)
						ShowCertInfo(pCertContext, L"Server Received Client Certificate");
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
			m_encrypting = true;
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

	// Something is wrong, we exited the loop abnormally
	DebugMsg("Unexpected scRet value %lx", scRet);
	m_LastError = scRet;
	return false;
}

// In theory a connection may switch in and out of SSL mode but
// that's rare and this implementation does not support it (it's 
// challenging to separate the SSL shutdown message from unencrypted
// messages following it). So, this just sends a shutdown message.
HRESULT CSSLServer::Disconnect(void)
{

	if (!m_encrypting)
	{
		DebugMsg("Disconnect called when we are not encrypting");
		return E_NOT_VALID_STATE;
	}

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

	Status = g_pSSPI->ApplyControlToken(m_hContext.getunsaferef(), &OutBuffer);

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
		&hServerCreds,				// Which certificate to use, already established
		m_hContext.getunsaferef(),				  	// The context handle
		NULL,						// Input buffer list
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

		m_encrypting = false;
		DebugMsg(" ");
		DebugMsg("%d bytes of data sent to notify SCHANNEL_SHUTDOWN", cbData);
		PrintHexDump(cbData, pbMessage);
	}
	return S_OK;
}

// End of CSSLServer declarations