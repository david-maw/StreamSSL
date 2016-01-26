#include "stdafx.h"
#include "SSLClient.h"
#include "SSLHelper.h"
#include "ActiveSock.h"

// Global value to optimize access since it is set only once
PSecurityFunctionTable CSSLClient::g_pSSPI = NULL;

// The CSSLClient class, this declares an SSL client side implementation that requires
// some means to send messages to a server (a CActiveSock).
CSSLClient::CSSLClient(CActiveSock * SocketStream)
	:readBufferBytes(0)
	,plainTextBytes(0)
	,readPtr(readBuffer)
	,m_SocketStream(SocketStream)
	,m_LastError(0)
{
	m_hContext.dwLower = m_hContext.dwUpper = ((ULONG_PTR) ((INT_PTR)-1)); // Invalidate it
}

CSSLClient::~CSSLClient(void)
{
	if (m_hContext.dwUpper != ((ULONG_PTR) ((INT_PTR)-1)))
		g_pSSPI->DeleteSecurityContext(&m_hContext);
}

// Avoid using (or exporting) g_pSSPI directly to give us some flexibility in case we want
// to change implementation later
PSecurityFunctionTable CSSLClient::SSPI(void){return g_pSSPI;}

// Set up the connection, including SSL handshake, certificate selection/validation
// lpBuf and Len let you provide any data that's already been read
HRESULT CSSLClient::Initialize(LPCWSTR ServerName, const void * const lpBuf, const int Len)
{
	HRESULT hr = S_OK;
	ServerCertNameMatches = false;
	ServerCertTrusted = false;

	if (!g_pSSPI)
	{
		hr = InitializeClass();
		if FAILED(hr)
			return hr;
	}
   PCCERT_CONTEXT pCertContext = NULL;
   if (SelectClientCertificate)
      hr = SelectClientCertificate(pCertContext, NULL, false);
   // If a certificate is required, it will be requested later 
   if FAILED(hr) pCertContext = NULL;
   hr = CreateCredentialsFromCertificate(&m_ClientCreds, pCertContext);
   if (pCertContext != NULL)
      CertFreeCertificateContext(pCertContext);
   if FAILED(hr) return hr;

	if (lpBuf && (Len>0))
	{  // preload the IO buffer with whatever we already read
		readBufferBytes = Len;
		memcpy_s(readBuffer, sizeof(readBuffer), lpBuf, Len);
	}
	else
		readBufferBytes = 0;
	// Perform SSL handshake
	hr = SSPINegotiateLoop(ATL::CW2T(ServerName));
	if(FAILED(hr))
	{
		DebugMsg("Couldn't connect");
		return hr;
	}

	// Find out how big the header and trailer will be:

	hr = g_pSSPI->QueryContextAttributes(&m_hContext, SECPKG_ATTR_STREAM_SIZES, &Sizes);

	if(FAILED(hr))
	{
		DebugMsg("Couldn't get Sizes, hr=%#x", hr);
		return hr;
	}

	return S_OK;
}

// Establish SSPI pointer and correct credentials (meaning pick a certificate) for the SSL server
HRESULT CSSLClient::InitializeClass(void)
{
   g_pSSPI = InitSecurityInterface();

   if(g_pSSPI == NULL)
   {
		int err = ::GetLastError();
		if (err == 0)
			return E_FAIL;
		else
			return HRESULT_FROM_WIN32(err);
   }
   return S_OK;
}

// Return the last error value for this CSSLClient
DWORD CSSLClient::GetLastError(void)
{
	if (m_LastError)
		return m_LastError;
	else
		return m_SocketStream->GetLastError();
}

// Because SSL is message oriented these calls send (or receive) a whole message
int CSSLClient::RecvPartial(LPVOID lpBuf, const ULONG Len)
{
	if (plainTextBytes > 0)
	{	// There are stored bytes, just return them
		DebugMsg("There is cached plaintext %d bytes", plainTextBytes);
		if (false) PrintHexDump(plainTextBytes, plainTextPtr);

		// Move the data to the output stream

		if (Len >= plainTextBytes)
		{
			int bytesReturned = plainTextBytes;
         DebugMsg("All %d cached plaintext bytes can be returned", plainTextBytes);
			if (false) PrintHexDump(plainTextBytes, plainTextPtr);
			memcpy_s(lpBuf, Len, plainTextPtr, plainTextBytes);
         plainTextBytes = 0;
			return bytesReturned;
		}
		else
		{	// More bytes are stored than the caller requested, so return some, store the rest until the next call
			memcpy_s(lpBuf, Len, plainTextPtr, Len);
			plainTextPtr += Len;
         plainTextBytes -= Len;
			DebugMsg("%d cached plaintext bytes can be returned, %d remain", Len, plainTextBytes);
			if (false) PrintHexDump(plainTextBytes, plainTextPtr);
			return Len;
		}
	}

   // plainTextBytes == 0 at this point

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
		DebugMsg("Using the saved %d bytes from server", readBufferBytes);
		if (false) PrintHexDump(readBufferBytes, readPtr);
		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;
		scRet = g_pSSPI->DecryptMessage(&m_hContext, &Message, 0, NULL);
	}

	while (scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
      int freeBytesAtStart = static_cast<int>((CHAR*)readPtr - &readBuffer[0]); 
      int freeBytesAtEnd = static_cast<int>(sizeof(readBuffer)) - readBufferBytes - freeBytesAtStart;
      if (freeBytesAtEnd == 0) // There is no space to add more at the end of the buffer
      {
         if (freeBytesAtStart > 0) // which ought to always be true at this point
         {
            // Move down the existing data to make room for more at the end of the buffer
            memmove_s(readBuffer, sizeof(readBuffer), readPtr, static_cast<int>(sizeof(readBuffer)) - freeBytesAtStart);
            freeBytesAtEnd = freeBytesAtStart;
            readPtr = readBuffer;
         }
         else
         {
				DebugMsg("RecvMsg Buffer inexplicably full");
			   return SOCKET_ERROR;
         }
      }
      err = m_SocketStream->RecvPartial((CHAR*)readPtr + readBufferBytes, freeBytesAtEnd);
		m_LastError = 0; // Means use the one from m_SocketStream
		if ((err == SOCKET_ERROR) || (err == 0))
		{
			if(WSA_IO_PENDING == m_SocketStream->GetLastError())
				DebugMsg("RecvMsg timed out");
			else if (WSAECONNRESET == m_SocketStream->GetLastError())
				DebugMsg("RecvMsg failed, the socket was closed by the other host");
			else
				DebugMsg("RecvMsg failed: %ld", m_SocketStream->GetLastError());
			return SOCKET_ERROR;
		}
		DebugMsg(" ");
		DebugMsg("Received %d bytes of ciphertext from server", err);
		if (false) PrintHexDump(err, (CHAR*)readPtr + readBufferBytes);
		readBufferBytes += err;

		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = readBufferBytes;
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		scRet = g_pSSPI->DecryptMessage(&m_hContext, &Message, 0, NULL);
	}
	

	if(scRet == SEC_E_OK)
		DebugMsg("Decrypted message from server.");
	else if(scRet == SEC_I_CONTEXT_EXPIRED)
	{
      DebugMsg("Server signalled end of session");
		m_LastError = scRet;
		return SOCKET_ERROR;
	}
	else
	{
		DebugMsg("Couldn't decrypt data from server, error %lx", scRet);
		m_LastError = scRet;
		return SOCKET_ERROR;
	}
	// There's a legitimate case here of a server wanting to renegotiate the session
	// by returning SEC_I_RENEGOTIATE. This code does not support it.

	// Locate the data buffer because the decrypted data is placed there. It's almost certainly
	// the second buffer (index 1) and we start there, but search all but the first just in case...
	PSecBuffer pDataBuffer(NULL);

	for(i = 1; i < 4; i++)
	{
		if(Buffers[i].BufferType == SECBUFFER_DATA)
		{
			pDataBuffer = &Buffers[i];
			break;
		}
	}

	if(!pDataBuffer)
	{
		DebugMsg("No data returned");
		m_LastError = WSASYSCALLFAILURE;
		return SOCKET_ERROR;
	}
	DebugMsg(" ");
	DebugMsg("Decrypted message has %d bytes", pDataBuffer->cbBuffer);
	if (false) PrintHexDump(pDataBuffer->cbBuffer, pDataBuffer->pvBuffer);

	// Move the data to the output stream

	if (Len >= int(pDataBuffer->cbBuffer)) 
		memcpy_s(lpBuf, Len, pDataBuffer->pvBuffer, pDataBuffer->cbBuffer);
	else
	{	// More bytes were decoded than the caller requested, so return some, store the rest until the next call
		memcpy_s(lpBuf, Len, pDataBuffer->pvBuffer, Len);
		plainTextBytes = pDataBuffer->cbBuffer - Len;
      plainTextPtr = plainText;
   	DebugMsg("Extra %d plaintext bytes stored", plainTextBytes);
		if (memcpy_s(plainText, sizeof(plainText), (char*)pDataBuffer->pvBuffer + Len, plainTextBytes))
		{
   		m_LastError = WSAEMSGSIZE;
   		return SOCKET_ERROR;
		}
		else
			pDataBuffer->cbBuffer = Len; // Pretend we only saw Len bytes
	}

	// See if there was any extra data read beyond what was needed for the message we are handling
	// TCP can sometime merge multiple messages into a single one, if there is, it will amost 
	// certainly be in the fourth buffer (index 3), but search all but the first, just in case.
	PSecBuffer pExtraDataBuffer(NULL);

	for(i = 1; i < 4; i++)
	{
		if(Buffers[i].BufferType == SECBUFFER_EXTRA)
		{
			pExtraDataBuffer = &Buffers[i];
			break;
		}
	}

	if(pExtraDataBuffer)
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
} // ReceivePartial

// Send an encrypted message containing an encrypted version of 
// whatever plaintext data the caller provides
int CSSLClient::SendPartial(LPCVOID lpBuf, const ULONG Len)
{
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

	scRet = g_pSSPI->EncryptMessage(&m_hContext, 0, &Message, 0);

	DebugMsg(" ");
	DebugMsg("Plaintext message has %d bytes", Len);
	if (false) PrintHexDump(Len, lpBuf);

	if (FAILED(scRet))
	{
		DebugMsg("EncryptMessage failed with %#x", scRet );
		m_LastError = scRet;
		return SOCKET_ERROR;
	}

	err = m_SocketStream->SendMsg(writeBuffer, Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	m_LastError = 0;

	DebugMsg("SendPartial %d encrypted bytes to server", Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	if (false) PrintHexDump(Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer, writeBuffer);
	if (err == SOCKET_ERROR)
	{
		DebugMsg( "SendPartial failed: %ld", m_SocketStream->GetLastError());
		return SOCKET_ERROR;
	}
	return Len;
} // SendPartial

// Negotiate a connection with the server, sending and receiving messages until the
// negotiation succeeds or fails
SECURITY_STATUS CSSLClient::SSPINegotiateLoop(TCHAR* ServerName)
{
	int cbData;
	TimeStamp            tsExpiry;
	SECURITY_STATUS      scRet;
	SecBufferDesc        InBuffer;
	SecBufferDesc        OutBuffer;
	SecBuffer            InBuffers[2];
	SecBuffer            OutBuffers[1];
	DWORD                err = 0;
	DWORD                dwSSPIFlags = 0;
	bool						ContextHandleValid = (m_hContext.dwUpper != ((ULONG_PTR) ((INT_PTR)-1))); 

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_REQ_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
						ISC_REQ_MANUAL_CRED_VALIDATION | // We'll check the certificate ourselves
                  ISC_REQ_STREAM;

    //
    //  Initiate a ClientHello message and generate a token.
    //

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

	 scRet = g_pSSPI->InitializeSecurityContext(
		 &m_ClientCreds,
		 NULL,
		 ServerName,
		 dwSSPIFlags,
		 0,
		 SECURITY_NATIVE_DREP,
		 NULL,
		 0,
		 &m_hContext,
		 &OutBuffer,
		 &dwSSPIFlags,
		 &tsExpiry);

    if(scRet != SEC_I_CONTINUE_NEEDED)
    {
		 DebugMsg("**** Error %#x returned by InitializeSecurityContext (1)", scRet);
        return scRet;
    }

    // Send response to server if there is one.
    if(OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
		 cbData = m_SocketStream->SendMsg(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
        if(cbData != OutBuffers[0].cbBuffer)
        {
            DebugMsg("**** Error %d sending data to server (1)", WSAGetLastError());
            g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
				g_pSSPI->DeleteSecurityContext(&m_hContext);
            return SEC_E_INTERNAL_ERROR;
        }

        DebugMsg("%d bytes of handshake data sent", cbData);

        if(false)
        {
            PrintHexDump(cbData, OutBuffers[0].pvBuffer);
            DebugMsg("\n");
        }

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
        OutBuffers[0].pvBuffer = NULL;
    }

	// Now start loop to negotiate SSL 
    DWORD           dwSSPIOutFlags;
    DWORD           cbIoBuffer;
    BOOL            fDoRead;


    cbIoBuffer = 0;

    fDoRead = TRUE; // do an initial read

    // 
    // Loop until the handshake is finished or an error occurs.
    //

    while(scRet == SEC_I_CONTINUE_NEEDED        ||
          scRet == SEC_E_INCOMPLETE_MESSAGE     ||
          scRet == SEC_I_INCOMPLETE_CREDENTIALS) 
   {

        //
        // Read data from server.
        //

        if(0 == cbIoBuffer || scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            if(fDoRead)
            {
					cbData = m_SocketStream->RecvPartial(readBuffer + cbIoBuffer, sizeof(readBuffer) - cbIoBuffer);
                if(cbData == SOCKET_ERROR)
                {
                   DebugMsg("**** Error %d reading data from server", WSAGetLastError());
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }
                else if(cbData == 0)
                {
                    DebugMsg("**** Server unexpectedly disconnected");
                    scRet = SEC_E_INTERNAL_ERROR;
                    break;
                }

                DebugMsg("%d bytes of handshake data received", cbData);

                if(debug)
                {
                    PrintHexDump(cbData, readBuffer + cbIoBuffer);
                    DebugMsg("\n");
                }

                cbIoBuffer += cbData;
            }
            else
            {
                fDoRead = TRUE;
            }
        }


        //
        // Set up the input buffers. Buffer 0 is used to pass in data
        // received from the server. Schannel will consume some or all
        // of this. Leftover data (if any) will be placed in buffer 1 and
        // given a buffer type of SECBUFFER_EXTRA.
        //

        InBuffers[0].pvBuffer   = readBuffer;
        InBuffers[0].cbBuffer   = cbIoBuffer;
        InBuffers[0].BufferType = SECBUFFER_TOKEN;

        InBuffers[1].pvBuffer   = NULL;
        InBuffers[1].cbBuffer   = 0;
        InBuffers[1].BufferType = SECBUFFER_EMPTY;

        InBuffer.cBuffers       = 2;
        InBuffer.pBuffers       = InBuffers;
        InBuffer.ulVersion      = SECBUFFER_VERSION;

        //
        // Set up the output buffers. These are initialized to NULL
        // so as to make it less likely we'll attempt to free random
        // garbage later.
        //

        OutBuffers[0].pvBuffer  = NULL;
        OutBuffers[0].BufferType= SECBUFFER_TOKEN;
        OutBuffers[0].cbBuffer  = 0;

        OutBuffer.cBuffers      = 1;
        OutBuffer.pBuffers      = OutBuffers;
        OutBuffer.ulVersion     = SECBUFFER_VERSION;

        //
        // Call InitializeSecurityContext.
        //

        scRet = g_pSSPI->InitializeSecurityContext(&m_ClientCreds,
                                          &m_hContext,
                                          NULL,
                                          dwSSPIFlags,
                                          0,
                                          SECURITY_NATIVE_DREP,
                                          &InBuffer,
                                          0,
                                          NULL,
                                          &OutBuffer,
                                          &dwSSPIOutFlags,
                                          &tsExpiry);

        //
        // If InitializeSecurityContext was successful (or if the error was 
        // one of the special extended ones), send the contends of the output
        // buffer to the server.
        //

        if(scRet == SEC_E_OK                ||
           scRet == SEC_I_CONTINUE_NEEDED   ||
           FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
        {
           // Get the server supplied certificate in order to decide whether it is acceptable

           PCERT_CONTEXT pServerCertContext = NULL;

           HRESULT hr = g_pSSPI->QueryContextAttributes(&m_hContext, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pServerCertContext);

           if (FAILED(hr))
           {
              if (hr == SEC_E_INVALID_HANDLE)
                 DebugMsg("QueryContextAttributes for cert returned SEC_E_INVALID_HANDLE, which is normal");
              else
                 DebugMsg("Couldn't get server certificate, hr=%#x", hr);
           }
           else
           {
              DebugMsg("Server Certificate returned");
              hr = CertNameMatches(pServerCertContext, ATL::CW2T(ServerName));
              ServerCertNameMatches = hr == S_OK;
              hr = CertTrusted(pServerCertContext);
              ServerCertTrusted = hr == S_OK;
              bool IsServerCertAcceptable = ServerCertAcceptable == nullptr;
              if (!IsServerCertAcceptable)
                 IsServerCertAcceptable = ServerCertAcceptable(pServerCertContext, ServerCertTrusted, ServerCertNameMatches);
              CertFreeCertificateContext(pServerCertContext);
              if (!IsServerCertAcceptable)
                 return SEC_E_UNKNOWN_CREDENTIALS;
           }

           if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
            {
					cbData = this->m_SocketStream->SendMsg(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
                if(cbData == SOCKET_ERROR || cbData == 0)
                {
						  DWORD err = m_SocketStream->GetLastError();
						  if (err = WSAECONNRESET)
							  DebugMsg("**** Server closed the connection unexpectedly");
						  else
	                    DebugMsg("**** Error %d sending data to server (2)", err);
                    g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                    g_pSSPI->DeleteSecurityContext(&m_hContext);
                    return SEC_E_INTERNAL_ERROR;
                }

                DebugMsg("%d bytes of handshake data sent", cbData);

                if(true)
                {
                    PrintHexDump(cbData, OutBuffers[0].pvBuffer);
                    DebugMsg("\n");
                }

                // Free output buffer.
                g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
                OutBuffers[0].pvBuffer = NULL;
            }
        }


        //
        // If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
        // then we need to read more data from the server and try again.
        //

        if(scRet == SEC_E_INCOMPLETE_MESSAGE)
        {
            continue;
        }

        //
        // If InitializeSecurityContext returned SEC_E_OK, then the 
        // handshake completed successfully.
        //

        if (scRet == SEC_E_OK)
        {
            //
            // If the "extra" buffer contains data, this is encrypted application
            // protocol layer stuff. It needs to be saved. The application layer
            // will later decrypt it with DecryptMessage.
            //

            DebugMsg("Handshake was successful");

            if(InBuffers[1].BufferType == SECBUFFER_EXTRA)
            {

					MoveMemory(readBuffer,
                           readBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                           InBuffers[1].cbBuffer);

					readBufferBytes = InBuffers[1].cbBuffer;

                DebugMsg("%d bytes of app data was bundled with handshake data", readBufferBytes);
            }
            else
            {
                readBufferBytes = 0;
            }

            //
            // Bail out to quit
            //

            break;
        }


        //
        // Check for fatal error.
        //

        if(FAILED(scRet))
        {
			  DebugMsg("**** Error %#x returned by InitializeSecurityContext (2)", scRet);
            break;
        }


        //
        // If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
        // then the server just requested client authentication. 
        //

        if(scRet == SEC_I_INCOMPLETE_CREDENTIALS)
        {
            //
            // The server has requested client authentication and
            // the credential we supplied didn't contain an acceptable 
			   // client certificate.
            //

            // 
            // This function will read the list of trusted certificate
            // authorities ("issuers") that was received from the server
            // and attempt to find a suitable client certificate that
            // was issued by one of these. If this function is successful, 
            // then we will connect using the new certificate. Otherwise,
            // we will attempt to connect anonymously (using our current
            // credentials).
            //

            // 
            // Note the a server will NOT send an issuer list if it has the registry key
            // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
            // has a DWORD value called SendTrustedIssuerList set to 0
            //

			   scRet = GetNewClientCredentials();

            // Go around again.
            if (scRet == SEC_E_OK)
            {
               fDoRead = FALSE;
               scRet = SEC_I_CONTINUE_NEEDED;
               continue;
            }
            else
            {
               DebugMsg("**** Error %08x returned by GetNewClientCredentials", scRet);
               break;
            }
        }


        //
        // Copy any leftover data from the "extra" buffer, and go around
        // again.
        //

        if ( InBuffers[1].BufferType == SECBUFFER_EXTRA )
        {
            MoveMemory(readBuffer,
                       readBuffer + (cbIoBuffer - InBuffers[1].cbBuffer),
                       InBuffers[1].cbBuffer);

            cbIoBuffer = InBuffers[1].cbBuffer;
        }
        else
        {
            cbIoBuffer = 0;
        }
    }

    // Delete the security context in the case of a fatal error.
    if(FAILED(scRet))
    {
		 g_pSSPI->DeleteSecurityContext(&m_hContext);
    }

    return scRet;
}

bool CSSLClient::Close()
{
	Disconnect();
	return m_SocketStream->Close();
}

HRESULT CSSLClient::Disconnect(void)
{
    DWORD           dwType;
    PBYTE           pbMessage;
    DWORD           cbMessage;
    DWORD           cbData;

    SecBufferDesc   OutBuffer;
    SecBuffer       OutBuffers[1];
    DWORD           dwSSPIFlags;
    DWORD           Status;

    //
    // Notify schannel that we are about to close the connection.
    //

    dwType = SCHANNEL_SHUTDOWN;

    OutBuffers[0].pvBuffer   = &dwType;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = sizeof(dwType);

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    Status = g_pSSPI->ApplyControlToken(&m_hContext, &OutBuffer);

    if(FAILED(Status)) 
    {
        DebugMsg("**** Error 0x%x returned by ApplyControlToken", Status);
        return Status;
    }

    //
    // Build an SSL close notify message.
    //

    dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT   |
                  ISC_REQ_REPLAY_DETECT     |
                  ISC_REQ_CONFIDENTIALITY   |
                  ISC_RET_EXTENDED_ERROR    |
                  ISC_REQ_ALLOCATE_MEMORY   |
                  ISC_REQ_STREAM;

    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;
    OutBuffers[0].cbBuffer   = 0;

    OutBuffer.cBuffers  = 1;
    OutBuffer.pBuffers  = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;

    pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
    cbMessage = OutBuffers[0].cbBuffer;


    //
    // Send the close notify message to the server.
    //

    if(pbMessage != NULL && cbMessage != 0)
    {
		 cbData = m_SocketStream->SendPartial(pbMessage, cbMessage);
        if(cbData == SOCKET_ERROR || cbData == 0)
        {
            Status = WSAGetLastError();
            DebugMsg("**** Error %d sending close notify", Status);
            return Status;
        }

        DebugMsg("Sending Close Notify");
        DebugMsg("%d bytes of handshake data sent", cbData);

        if(true)
        {
            PrintHexDump(cbData, pbMessage);
            DebugMsg("\n");
        }

        // Free output buffer.
        g_pSSPI->FreeContextBuffer(pbMessage);
    }

    return Status;
}

bool CSSLClient::getServerCertNameMatches()
{
	return ServerCertNameMatches;
}

bool CSSLClient::getServerCertTrusted()
{
	return ServerCertTrusted;
}

SECURITY_STATUS CSSLClient::GetNewClientCredentials()
{
    CredHandle hCreds;
    SecPkgContext_IssuerListInfoEx IssuerListInfo;
    SECURITY_STATUS Status;

    // Destroy the cached credentials.
    g_pSSPI->FreeCredentialsHandle(&m_ClientCreds);

    //
    // Read list of trusted issuers from schannel.
    // 
    // Note the a server will NOT send an issuer list if it has the registry key
    // HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
    // has a DWORD value called SendTrustedIssuerList set to 0
    //

    Status = g_pSSPI->QueryContextAttributes(&m_hContext,
                                    SECPKG_ATTR_ISSUER_LIST_EX,
                                    (PVOID)&IssuerListInfo);
    if(Status != SEC_E_OK)
    {
        DebugMsg("Error 0x%08x querying issuer list info", Status);
        return Status;
    }

    DebugMsg("Issuer list information returned, issuers = %d", IssuerListInfo.cIssuers);

    // Now go ask for the client credentials
    PCCERT_CONTEXT pCertContext = NULL;
    if (SelectClientCertificate)
       Status = SelectClientCertificate(pCertContext, &IssuerListInfo, true);
    if(FAILED(Status))
    {
        DebugMsg("Error 0x%08x selecting client certificate", Status);
        return Status;
    }

    if (!pCertContext)
       DebugMsg("No suitable client certificate is available to return to the server");
    
    Status = CreateCredentialsFromCertificate(&hCreds, pCertContext);

    if (SUCCEEDED(Status) && SecIsValidHandle(&hCreds))
    {
        // Store the new ones
        m_ClientCreds = hCreds;
    }

    return Status;

    //
    // Many applications maintain a global credential handle that's
    // anonymous (that is, it doesn't contain a client certificate),
    // which is used to connect to all servers. If a particular server
    // should require client authentication, then a new credential 
    // is created for use when connecting to that server. The global
    // anonymous credential is retained for future connections to
    // other servers.
    //
    // Maintaining a single anonymous credential that's used whenever
    // possible is most efficient, since creating new credentials all
    // the time is rather expensive.
    //
}

SECURITY_STATUS CSSLClient::CreateCredentialsFromCertificate(PCredHandle phCreds, PCCERT_CONTEXT pCertContext)
{
   // Build Schannel credential structure.
   SCHANNEL_CRED   SchannelCred = { 0 };
   SchannelCred.dwVersion = SCHANNEL_CRED_VERSION;
   if (pCertContext)
   {
      SchannelCred.cCreds = 1;
      SchannelCred.paCred = &pCertContext;
   }
   SchannelCred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT;
   SchannelCred.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;

   SECURITY_STATUS Status;
   TimeStamp       tsExpiry;
   // Get a handle to the SSPI credential
   Status = g_pSSPI->AcquireCredentialsHandle(
      NULL,                   // Name of principal
      UNISP_NAME,             // Name of package
      SECPKG_CRED_OUTBOUND,   // Flags indicating use
      NULL,                   // Pointer to logon ID
      &SchannelCred,          // Package specific data
      NULL,                   // Pointer to GetKey() func
      NULL,                   // Value to pass to GetKey()
      phCreds,                // (out) Cred Handle
      &tsExpiry);             // (out) Lifetime (optional)

   if (Status != SEC_E_OK)
   {
      DWORD dw = ::GetLastError();
      if (Status == SEC_E_UNKNOWN_CREDENTIALS)
         DebugMsg("**** Error: 'Unknown Credentials' returned by AcquireCredentialsHandle. LastError=%d", dw);
      else
         DebugMsg("**** Error 0x%x returned by AcquireCredentialsHandle. LastError=%d.", Status, dw);
      return Status;
   }

   return SEC_E_OK;
}
