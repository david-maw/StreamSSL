#include "pch.h"

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
#define SCHANNEL_USE_BLACKLISTS
#include <schannel.h>
#include "SSLClient.h"
#include "Utilities.h"
#include "SSLHelper.h"
#include "ActiveSock.h"
#include "SecurityHandle.h"
#include "CertHelper.h"

// The CSSLClient class, this declares an SSL client side implementation that requires
// some means to send messages to a server (a CActiveSock).
CSSLClient::CSSLClient(CActiveSock *SocketStream)
	: m_SocketStream(SocketStream)
	, readPtr(readBuffer)
{
}

// Set up the connection, including SSL handshake, certificate selection/validation
// lpBuf and Len let you provide any data that's already been read
HRESULT CSSLClient::Initialize(std::wstring ServerName, const void * const lpBuf, const int Len)
{
	HRESULT hr = S_OK;
	ServerCertNameMatches = false;
	ServerCertTrusted = false;

	if (!g_pSSPI)
	{
		hr = InitializeClass();
		if FAILED(hr)
			return hr;
		if (!g_pSSPI) // InitializeClass should have assigned g_pSSPI if it worked
			return E_POINTER;
	}
	CertContextHandle hCertContext;
	this->ServerName = ServerName;
	if (SelectClientCertificate)
	{
		hr = SelectClientCertificate(*hCertContext.set(), NULL, false);
		if FAILED(hr)
			DebugMsg("Optional client certificate not selected");
	}
	// If a certificate is required, it will be requested later 
	hr = CreateCredentialsFromCertificate(m_ClientCreds.set(), hCertContext.get());
	if FAILED(hr) return hr;

	if (lpBuf && (Len > 0))
	{  // preload the IO buffer with whatever we already read
		readBufferBytes = Len;
		memcpy_s(readBuffer, sizeof(readBuffer), lpBuf, Len);
	}
	else
		readBufferBytes = 0;
	// Perform SSL handshake
	hr = SSPINegotiate(ServerName.c_str());
	if (FAILED(hr))
	{
		DebugHresult("Couldn't connect", hr);
		return hr;
	}

	// Find out how big the header and trailer will be:

	hr = g_pSSPI->QueryContextAttributes(m_hContext.getunsaferef(), SECPKG_ATTR_STREAM_SIZES, &Sizes);

	if (FAILED(hr))
	{
		DebugHresult("Couldn't get Sizes,", hr);
		return hr;
	}

	return S_OK;
}

// Establish SSPI pointer and correct credentials (meaning pick a certificate) for the SSL server
HRESULT CSSLClient::InitializeClass()
{
	if (g_pSSPI == nullptr)
	{
		return E_FAIL;
	}
	return S_OK;
}

// Return the last error value for this CSSLClient
DWORD CSSLClient::GetLastError() const
{
	if (m_LastError)
		return m_LastError;
	else
		return m_SocketStream->GetLastError();
}

/// <summary>
/// Read data from the socket into the readBuffer. This is called by RecvPartialEncrypted to get more data when needed.
/// </summary>
/// <returns>The number of bytes read or SOCKET_ERROR</returns>
int CSSLClient::GetDataFromSocket()
{
	if (m_SocketStream == nullptr)
		return SOCKET_ERROR;
	size_t freeBytesAtStart = static_cast<int>((CHAR*)readPtr - &readBuffer[0]);
	size_t freeBytesAtEnd = static_cast<int>(sizeof(readBuffer)) - readBufferBytes - freeBytesAtStart;
    size_t remainingPacketLength = 0;
	int recvResult = 0;
	if (false) // Set true to read one packet at a time for ease of debugging
	{
		if (remainingPacketLength == 0) // try and read a single message to make debugging a little easier
		{
			recvResult = m_SocketStream->Recv(readBuffer, 5, 5); // Read the packet Header
			if (recvResult == 5)
			{
				remainingPacketLength = ((UINT8)readBuffer[3] << 8) + (UINT8)readBuffer[4];
				recvResult = m_SocketStream->Recv(readBuffer + 5, remainingPacketLength); // concatenate the variable part of the message
				if (recvResult > 0)
				{
					remainingPacketLength -= recvResult;
					recvResult += 5; // add the packet header bytes in
					if (remainingPacketLength != 0)
						DebugMsg("Partial packet read, readBufferBytes = %d, remainingPacketLength = %d", readBufferBytes, remainingPacketLength);
				}
			}
			else
			{
				int lastError = WSAGetLastError();
				if (lastError != 0)
					DebugHresult("**** Error reading packet header from server ", HRESULT_FROM_WIN32(lastError));
				else if (recvResult == 0)
					DebugMsg("**** No packet header data returned by server, probably the socket closed");
				else
					DebugMsg("**** Wrong amount of packet header data returned by server, readBufferBytes = %d", readBufferBytes);
				recvResult = SOCKET_ERROR;
			}
		}
		else if (remainingPacketLength > 0) // read the remainder of a partial message
		{
			if (remainingPacketLength > sizeof(readBuffer) - freeBytesAtEnd)
				recvResult = m_SocketStream->Recv((CHAR*)readPtr + recvResult, remainingPacketLength);
			if (recvResult > 0)
			{
				remainingPacketLength -= recvResult;
			}
		}
		else
		{
			DebugMsg("**** Error reading single packet");
			return NTE_INTERNAL_ERROR;
		}
	}
    else // Read as much as will fit in the buffer, this is the normal case when we're not debugging
		recvResult = m_SocketStream->Recv((CHAR*)readPtr + readBufferBytes, freeBytesAtEnd);
	if (recvResult == SOCKET_ERROR)
	{
		m_LastError = m_SocketStream->GetLastError();
		return SOCKET_ERROR;
	}
	else if (recvResult == 0)
	{
		m_LastError = WSAECONNRESET;
		return SOCKET_ERROR;
	}
	return recvResult;
}

int CSSLClient::Recv(LPVOID lpBuf, const size_t Len, const size_t MinLen)
{
	UNREFERENCED_PARAMETER(MinLen);
	if (plainTextBytes > 0)
	{	// There are stored bytes, just return them
		DebugMsg("There are cached plaintext %d bytes", plainTextBytes);
		if (false) PrintHexDump(plainTextBytes, plainTextPtr);

		// Move the data to the output stream

		if (Len >= plainTextBytes)
		{
			auto bytesReturned = plainTextBytes;
			DebugMsg("All %d cached plaintext bytes can be returned", plainTextBytes);
			if (false) PrintHexDump(plainTextBytes, plainTextPtr);
			memcpy_s(lpBuf, Len, plainTextPtr, plainTextBytes);
			plainTextBytes = 0;
			return static_cast<int>(bytesReturned);
		}
		else
		{	// More bytes are stored than the caller requested, so return some, store the rest until the next call
			memcpy_s(lpBuf, Len, plainTextPtr, Len);
			plainTextPtr += Len;
			plainTextBytes -= Len;
			DebugMsg("%d cached plaintext bytes can be returned, %d remain", Len, plainTextBytes);
			if (false) PrintHexDump(plainTextBytes, plainTextPtr);
			return static_cast<int>(Len);
		}
	}

	// plainTextBytes == 0 at this point, so we would actually need to read data from the network

	if (m_encrypting)
		return RecvPartialEncrypted(lpBuf, Len);
	else
	{
		DebugMsg("Receive can only be called when encrypting");
		m_LastError = ERROR_FILE_NOT_ENCRYPTED;
		return SOCKET_ERROR;
	}
}

// Because SSL is message oriented these calls send (or receive) a whole message
int CSSLClient::RecvPartialEncrypted(LPVOID lpBuf, const size_t Len)
{
	int i;
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

	DebugMsg(" "); // Make it clear in the diagnostic trace that we're dealing with a new message
	if (readBufferBytes == 0)
		scRet = SEC_E_INCOMPLETE_MESSAGE;
	else
	{	// There is already data in the buffer, so process it first
		DebugMsg("In RecvPartialEncrypted, using the saved %d bytes from server", readBufferBytes);
		if (false) PrintHexDump(readBufferBytes, readPtr);
		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = static_cast<unsigned long>(readBufferBytes);
		Buffers[0].BufferType = SECBUFFER_DATA;
		scRet = g_pSSPI->DecryptMessage(m_hContext.getunsaferef(), &Message, 0, nullptr);
		if (scRet == SEC_E_INCOMPLETE_MESSAGE) // We have a partial message, so we need to read more data from the socket, this is normal
			DebugMsg("In RecvPartialEncrypted, saved bytes were incomplete message, need to read more data");
		else
			DebugHresult("In RecvPartialEncrypted, DecryptMessage of saved bytes, scRet", scRet);
	}

	StartRecvTimer(); // The whole message must be received before timeout seconds elapse
	while (scRet == SEC_E_INCOMPLETE_MESSAGE)
	{
		size_t freeBytesAtStart = static_cast<int>((CHAR*)readPtr - &readBuffer[0]);
		size_t freeBytesAtEnd = static_cast<int>(sizeof(readBuffer)) - readBufferBytes - freeBytesAtStart;
		if (freeBytesAtEnd == 0) // There is no space to add more at the end of the buffer
		{
			if (freeBytesAtStart > 0) // which ought to always be true at this point
			{
				// Move down the existing data to make room for more at the end of the buffer
				memmove_s(readBuffer, sizeof(readBuffer), readPtr, sizeof(readBuffer) - freeBytesAtStart);
				freeBytesAtEnd = freeBytesAtStart;
				readPtr = readBuffer;
			}
			else
			{
				DebugMsg("Recv Buffer inexplicably full");
				return SOCKET_ERROR;
			}
		}
		const int err = GetDataFromSocket();
		m_LastError = 0; // Means use the error value stored in m_SocketStream
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
		DebugMsg("In RecvPartialEncrypted, received %d bytes of ciphertext from server", err);
		CSSLHelper::TracePacket((byte*)readPtr + readBufferBytes, err);
		readBufferBytes += err;

		Buffers[0].pvBuffer = readPtr;
		Buffers[0].cbBuffer = static_cast<unsigned long>(readBufferBytes);
		Buffers[0].BufferType = SECBUFFER_DATA;

		Buffers[1].BufferType = SECBUFFER_EMPTY;
		Buffers[2].BufferType = SECBUFFER_EMPTY;
		Buffers[3].BufferType = SECBUFFER_EMPTY;

		scRet = g_pSSPI->DecryptMessage(m_hContext.getunsaferef(), &Message, 0, nullptr);
		if (scRet == SEC_E_INCOMPLETE_MESSAGE) // We have a partial message, so we need to read more data from the socket, this is normal
			DebugMsg("In RecvPartialEncrypted loop, DecryptMessage says incomplete message, need to read more data");
		else
			DebugHresult("Will exit RecvPartialEncrypted loop, DecryptMessage returned scRet", scRet);
	}

	if (scRet == SEC_E_OK)
		DebugMsg("Decrypted message from server.");
	else if (scRet == SEC_I_CONTEXT_EXPIRED)
	{
		DebugMsg("Server signaled end of session");
		m_encrypting = false;
		m_LastError = scRet;
		return SOCKET_ERROR;
	}
	else if (scRet == SEC_I_RENEGOTIATE)
	{
		DebugMsg("In RecvPartialEncrypted, server sent renegotiate request, will enter SSPINegotiateLoop");

		PSecBuffer pDataBuffer(nullptr);

		for (i = 1; i < 4; i++)
		{
			if (Buffers[i].BufferType == SECBUFFER_EXTRA)
			{
				pDataBuffer = &Buffers[i];
				break;
			}
		}

		if (!pDataBuffer)
		{
			DebugMsg("No renegotiate data returned");
			m_LastError = WSASYSCALLFAILURE;
			return SOCKET_ERROR;
		}
		scRet = ActualSSPINegotiateLoop(ServerName.c_str(), pDataBuffer);
		if (FAILED(scRet))
		{
			DebugMsg("Renegotiate Failed, could not connect");
			m_LastError = scRet;
			return SOCKET_ERROR;
		}
		pDataBuffer->BufferType = SECBUFFER_EMPTY; // We have consumed it
        DebugMsg("Renegotiation completed, calling recursively to receive user data from server");
        return RecvPartialEncrypted(lpBuf, Len); // Call recursively to receive user data from the server
	}
	else if (scRet == SEC_E_DECRYPT_FAILURE)
	{
		DebugMsg("Couldn't decrypt data from server, DecryptMessageServer returned SEC_E_DECRYPT_FAILURE");
		m_encrypting = false;
		m_LastError = scRet;
		return SOCKET_ERROR;
	}
	else
	{
		DebugHresult("Couldn't decrypt data from server,", scRet);
		m_LastError = scRet;
		return SOCKET_ERROR;
	}

	// Locate the data buffer because the decrypted data is placed there. It's almost certainly
	// the second buffer (index 1) and we start there, but search all but the first just in case...
	PSecBuffer pDataBuffer(nullptr);

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
	DebugMsg("Decrypted message has %d bytes, read requested %d", pDataBuffer->cbBuffer, Len);
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
			pDataBuffer->cbBuffer = static_cast<unsigned long>(Len); // Pretend we only saw Len bytes
	}

	// See if there was any extra data read beyond what was needed for the message we are handling
	// TCP can sometime merge multiple messages into a single one, if there is, it will almost 
	// certainly be in the fourth buffer (index 3), but search all but the first, just in case.
	PSecBuffer pExtraDataBuffer(nullptr);

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
		CSSLHelper::TracePacket((byte*)readPtr, readBufferBytes);
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
int CSSLClient::Send(LPCVOID lpBuf, const size_t Len)
{
	if (!lpBuf || Len > MaxMsgSize)
		return SOCKET_ERROR;

	if (!m_encrypting)
	{
		DebugMsg("Send can only be called when encrypting");
		m_LastError = ERROR_FILE_NOT_ENCRYPTED;
		return SOCKET_ERROR;
	}

	int err;

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
	Buffers[1].cbBuffer = static_cast<unsigned long>(Len);
	Buffers[1].BufferType = SECBUFFER_DATA;

	Buffers[2].pvBuffer = writeBuffer + Sizes.cbHeader + Len;
	Buffers[2].cbBuffer = Sizes.cbTrailer;
	Buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	Buffers[3].BufferType = SECBUFFER_EMPTY;

	scRet = g_pSSPI->EncryptMessage(m_hContext.getunsaferef(), 0, &Message, 0);

	DebugMsg("In Send, plaintext message has %d bytes", Len);
	if (false) PrintHexDump(Len, lpBuf);

	if (FAILED(scRet))
	{
		DebugHresult("EncryptMessage failed,", scRet);
		m_LastError = scRet;
		return SOCKET_ERROR;
	}

	DebugMsg("CSSLClient::Send %d encrypted bytes to server", Buffers[0].cbBuffer + Buffers[1].cbBuffer + Buffers[2].cbBuffer);

	err = m_SocketStream->Send(writeBuffer, static_cast<size_t>(Buffers[0].cbBuffer) + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	m_LastError = 0;
	if (err == SOCKET_ERROR)
	{
		DebugHresult("CSSLClient::Send failed: %ld", HRESULT_FROM_WIN32(m_SocketStream->GetLastError()));
		return SOCKET_ERROR;
	}
	else
		CSSLHelper::TracePacket(writeBuffer, static_cast<size_t>(Buffers[0].cbBuffer) + Buffers[1].cbBuffer + Buffers[2].cbBuffer);
	return static_cast<int>(Len);
}

// Negotiate a connection with the server, sending and receiving messages until the
// negotiation succeeds or fails. The actual negotiation is done in a loop, so this function
// just sets up various state before calling the function that implements the negotiation loop 
// and then returns the result of invoking the negotiation loop.
SECURITY_STATUS CSSLClient::SSPINegotiate(LPCWCHAR ServerName)
{
	int cbData;
	TimeStamp            tsExpiry;
	SECURITY_STATUS      scRet;
	SecBufferDesc        OutBuffer;
	SecBuffer            OutBuffers[1];
	DWORD                dwSSPIFlags = 0;
	DWORD                dwSSPIOutFlags = 0;

	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
		ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_REQ_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_MANUAL_CRED_VALIDATION | // We'll check the certificate ourselves
		ISC_REQ_STREAM;

	//
	//  Initiate a ClientHello message and generate a token.
	//

	OutBuffers[0].pvBuffer = nullptr;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	DebugMsg("Enter SSPINegotiate, initial negotiation");
	scRet = g_pSSPI->InitializeSecurityContext(
		m_ClientCreds.getunsaferef(),          // phCredential - this parameter is not const correct so we just have to trust it
		nullptr,                               // phContext
		const_cast<SEC_WCHAR*>(ServerName),    // pszTargetName
		dwSSPIFlags,                           // fContextReq
		0,                                     // Reserved1
		0,                                     // TargetDataRep (not used with Schannel)
		nullptr,                               // pInput
		0,                                     // Reserved2
		m_hContext.set(),                      // phNewContext
		&OutBuffer,                            // pOutput
		&dwSSPIOutFlags,                       // pfContextAttr
		&tsExpiry);                            // ptsExpiry

	if (scRet != SEC_I_CONTINUE_NEEDED)
	{
		DebugHresult("**** Error returned by InitializeSecurityContext initial call", scRet);
		return scRet;
	}
	else
		DebugHresult("InitializeSecurityContext initial call", scRet);


	// Send response to server if there is one.
	if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != nullptr)
	{
		DebugMsg("Sending %d bytes of handshake data", OutBuffers[0].cbBuffer);
		cbData = m_SocketStream->Send(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
		if ((cbData == SOCKET_ERROR) || (cbData >= 0 && static_cast<unsigned long>(cbData) != OutBuffers[0].cbBuffer))
		{
			DebugMsg("**** Error %d sending data to server (1)", WSAGetLastError());
			g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
			if (cbData == SOCKET_ERROR)
				scRet = CRYPT_E_FILE_ERROR;
			else
				scRet = NTE_INTERNAL_ERROR;
		}
		else
		{
			DebugMsg(""); // Blank line to delimit new debug message
			DebugMsg("%d bytes of handshake data sent", cbData);
			CSSLHelper::TracePacket(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
			// Free output buffer.
			g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
			OutBuffers[0].pvBuffer = nullptr;
		}
	}

	scRet = ActualSSPINegotiateLoop(ServerName);

	// Delete the security context in the case of a fatal error.
	if (FAILED(scRet))
		m_hContext.Close();
	else
	{
		m_encrypting = true;

		if (debug)
		{
			//Get information about the connection, particularly if it's TLS 1.3 because if so we are not done.
			SecPkgContext_ConnectionInfo ConnectionInfo{};
			const SECURITY_STATUS qcaRet = g_pSSPI->QueryContextAttributes(m_hContext.getunsaferef(), SECPKG_ATTR_CONNECTION_INFO, &ConnectionInfo);

			if (qcaRet != SEC_E_OK)
			{
				DebugHresult("Couldn't get connection info", scRet);
				return E_FAIL;
			}

			if ((ConnectionInfo.dwProtocol & SP_PROT_TLS1_3_CLIENT) == SP_PROT_TLS1_3_CLIENT)
				DebugMsg("Exiting SSPINegotiate, established a TLS 1.3 Connection, KeyUpdate and NewSessionTicket are permitted and will return SEC_I_RENEGOTIATE from DecryptMessage");
		}
	}

	DebugHresult("Exit SSPINegotiate", scRet);
	return scRet;
}

SECURITY_STATUS CSSLClient::ActualSSPINegotiateLoop(LPCWCHAR ServerName, SecBuffer* pInitialBuffer)
{
	int cbData; // Result of the most recent red or write, which may be a partial packet
	TimeStamp            tsExpiry;
	SECURITY_STATUS      scRet = SEC_I_CONTINUE_NEEDED;
	SecBufferDesc        InBuffer, * pInBuffer = nullptr;
	SecBufferDesc        OutBuffer;
	SecBuffer            InBuffers[2];
	SecBuffer            OutBuffers[1];
	DWORD                dwSSPIFlags = 0;
	DWORD                dwSSPIOutFlags = 0;

	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
		ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_REQ_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_MANUAL_CRED_VALIDATION | // We'll check the certificate ourselves
		ISC_REQ_STREAM;

	// Now start loop to negotiate SSL 
	BOOL            fDoRead = pInitialBuffer == 0;

	// 
	// Loop until the handshake is finished or an error occurs.
	//

	DebugMsg("In ActualSSPINegotiateLoop, fDoRead=%d", (int)fDoRead);

	while (scRet == SEC_I_CONTINUE_NEEDED ||
		scRet == SEC_E_INCOMPLETE_MESSAGE ||
		scRet == SEC_I_INCOMPLETE_CREDENTIALS)
	{

		//
		// Read data from server.
		//

		DWORD remainingPacketLength = 0;

		if (0 == readBufferBytes || scRet == SEC_E_INCOMPLETE_MESSAGE)
		{
			if (fDoRead)
			{
				if (true) // Set true to read one packet at a time for ease of debugging
				{
					if (0 == readBufferBytes) // try and read a single message to make debugging a little easier
					{
						cbData = m_SocketStream->Recv(readBuffer, 5, 5); // Read the packet Header
						if (cbData == 5)
						{
							remainingPacketLength = ((UINT8)readBuffer[3] << 8) + (UINT8)readBuffer[4];
							cbData = m_SocketStream->Recv(readBuffer + 5, remainingPacketLength); // concatenate the variable part of the message
							if (cbData > 0)
							{
								remainingPacketLength -= cbData;
								cbData += 5; // add the packet header bytes in
								if (remainingPacketLength != 0)
									DebugMsg("Partial packet read, readBufferBytes = %d, remainingPacketLength = %d", readBufferBytes, remainingPacketLength);
							}
						}
						else
						{
							int lastError = WSAGetLastError();
							if (lastError != 0)
								DebugHresult("**** Error reading packet header from server ", HRESULT_FROM_WIN32(lastError));
							else if (cbData == 0)
								DebugMsg("**** No packet header data returned by server, probably the socket closed");
							else
								DebugMsg("**** Wring amount of packet header data returned by server, cbData = %d", cbData);
							scRet = NTE_INTERNAL_ERROR;
							break;
						}
					}
					else if (remainingPacketLength > 0) // read the remainder of a partial message
					{
						if (remainingPacketLength > sizeof(readBuffer) - readBufferBytes)
							cbData = m_SocketStream->Recv(readBuffer + readBufferBytes, remainingPacketLength);
						if (cbData > 0)
						{
							remainingPacketLength -= cbData;
						}
					}
					else
					{
						DebugMsg("**** Error reading single packet");
						scRet = NTE_INTERNAL_ERROR;
						break;
					}
				}
				else
					cbData = m_SocketStream->Recv(readBuffer + readBufferBytes, sizeof(readBuffer) - readBufferBytes);

				if (cbData == SOCKET_ERROR)
				{
					DebugHresult("**** Error reading data from server ", HRESULT_FROM_WIN32(WSAGetLastError()));
					scRet = NTE_INTERNAL_ERROR;
					break;
				}
				else if (cbData == 0)
				{
					DebugMsg("**** Server unexpectedly disconnected");
					scRet = NTE_INTERNAL_ERROR;
					break;
				}

				DebugMsg(""); // Blank line to delimit new message
				DebugMsg("%d bytes of handshake data received", cbData);

				if (cbData > 0)
				{
					DebugMsg("Retracing Previous Packet - additional data received");
					CSSLHelper::TracePacket(readBuffer, readBufferBytes + cbData);
				}
				readBufferBytes += cbData;
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

		
		if (pInitialBuffer == 0)
		{
			InBuffers[0].pvBuffer = readBuffer;
			InBuffers[0].cbBuffer = readBufferBytes;
		}
		else
		{
			InBuffers[0].pvBuffer = pInitialBuffer->pvBuffer;
			InBuffers[0].cbBuffer = pInitialBuffer->cbBuffer;
		}
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer = nullptr;
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

		OutBuffers[0].pvBuffer = nullptr;
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;
		OutBuffers[0].cbBuffer = 0;

		OutBuffer.cBuffers = 1;
		OutBuffer.pBuffers = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;

		//
		// Call InitializeSecurityContext.
		//

		scRet = g_pSSPI->InitializeSecurityContext(
			m_ClientCreds.getunsaferef(),    // phCredential - this parameter is not const correct so we just have to trust it
			m_hContext.getunsaferef(),       // phContext
			nullptr,                         // pszTargetName
			dwSSPIFlags,                     // fContextReq
			0,                               // Reserved1
			SECURITY_NATIVE_DREP,            // TargetDataRep (not used with Schannel)
			&InBuffer,                       // pInput
			0,                               // Reserved2
			nullptr,                         // phNewContext
			&OutBuffer,                      // pOutput
			&dwSSPIOutFlags,                 // pfContextAttr
			&tsExpiry);                      // ptsExpiry

		if (scRet == SEC_I_CONTINUE_NEEDED)
			DebugMsg("InitializeSecurityContext in loop returned SEC_I_CONTINUE_NEEDED so we must get more data and call it again");
		else
			DebugHresult("InitializeSecurityContext in loop", scRet);


		//
		// If InitializeSecurityContext was successful (or if the error was 
		// one of the special extended ones), send the contents of the output
		// buffer to the server.
		//

		if (scRet == SEC_E_OK ||
			scRet == SEC_I_CONTINUE_NEEDED ||
			FAILED(scRet) && (dwSSPIOutFlags & ISC_RET_EXTENDED_ERROR))
		{
			// Get the server supplied certificate in order to decide whether it is acceptable

			CertContextHandle hServerCertContext;

			HRESULT hr = g_pSSPI->QueryContextAttributes(m_hContext.getunsaferef(), SECPKG_ATTR_REMOTE_CERT_CONTEXT, hServerCertContext.set());

			if (FAILED(hr))
			{
				if (hr == SEC_E_INVALID_HANDLE)
					;//DebugMsg("QueryContextAttributes for cert returned SEC_E_INVALID_HANDLE, which usually means we don't have a server certificate yet");
				else
					DebugHresult("Couldn't get server certificate,", hr);
			}
			else
			{
				ServerCertNameMatches = MatchCertificateName(hServerCertContext.get(), ServerName);
				hr = CertTrusted(hServerCertContext.get(), false);
				ServerCertTrusted = hr == S_OK;
				bool IsServerCertAcceptable = ServerCertAcceptable == nullptr // by not providing a routine the user says any certificate is acceptable 
					|| ServerCertAcceptable(hServerCertContext.get(), ServerCertTrusted, ServerCertNameMatches); // call the user provided function to validate the certificate
				DebugBeginMsg();
				if (IsServerCertAcceptable) DebugContinueMsg("Acceptable"); else DebugContinueMsg("Unacceptable");
				DebugContinueMsg(" server certificate returned, %S", GetCertName(hServerCertContext.get()).c_str());
				if (ServerCertTrusted) DebugContinueMsg(", trusted"); else DebugContinueMsg(", untrusted");
				if (ServerCertNameMatches) DebugContinueMsg(", name matches"); else DebugContinueMsg(", name does not match");
				DebugEndMsg();
				if (!IsServerCertAcceptable)
					return SEC_E_UNKNOWN_CREDENTIALS;
			}

			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != nullptr)
			{
				cbData = this->m_SocketStream->Send(OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer);
				if (cbData == SOCKET_ERROR || cbData == 0)
				{
					DWORD err = m_SocketStream->GetLastError();
					if (err == WSAECONNRESET)
						DebugMsg("**** Server closed the connection unexpectedly");
					else
						DebugMsg("**** Error %d sending data to server (2)", err);
					g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
					m_hContext.Close();
					return NTE_INTERNAL_ERROR;
				}

				DebugMsg(""); // Blank line to delimit new message
				DebugMsg("%d bytes of handshake data sent", cbData);
				CSSLHelper::TracePacket(OutBuffers[0].pvBuffer, cbData);

				// Free output buffer.
				g_pSSPI->FreeContextBuffer(OutBuffers[0].pvBuffer);
				OutBuffers[0].pvBuffer = nullptr;
			}
		}

		//
		// If InitializeSecurityContext returned SEC_E_INCOMPLETE_MESSAGE,
		// then we need to read more data from the server and try again.
		//

		if (scRet == SEC_E_INCOMPLETE_MESSAGE)
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

			DebugMsg("InitializeSecurityContext in loop returned SEC_E_OK, the handshake was successful");

			if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
			{
				// Move the message to the beginning of the read buffer
				MoveMemory(readBuffer, 
					readBuffer + (readBufferBytes - InBuffers[1].cbBuffer),
					InBuffers[1].cbBuffer);
				readBufferBytes = InBuffers[1].cbBuffer;

				DebugMsg("%d bytes of additional data were bundled with handshake data", readBufferBytes);
				CSSLHelper::TracePacket(readBuffer, readBufferBytes);
			}
			else
			{
				readBufferBytes = 0;
			}
			break;
		}

		//
		// Check for fatal error.
		//

		if (FAILED(scRet))
		{
			DebugHresult("**** Error returned by InitializeSecurityContext (2)", scRet);
			break;
		}


		//
		// If InitializeSecurityContext returned SEC_I_INCOMPLETE_CREDENTIALS,
		// then the server just requested client authentication. 
		//

		if (scRet == SEC_I_INCOMPLETE_CREDENTIALS)
		{
			//
			// The server has requested client authentication and
			// the credential we supplied didn't contain an acceptable 
			// client certificate.
			//

			DebugMsg("Server requires a client certificate, finding one");

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
				DebugMsg("Client credentials obtained successfully");
				fDoRead = FALSE;
				scRet = SEC_I_CONTINUE_NEEDED;
				continue;
			}
			else
			{
				DebugHresult("**** Error returned by GetNewClientCredentials", scRet);
				break;
			}
		}

		//
		// Copy any leftover data from the "extra" buffer, and go around
		// again.
		//

		if (InBuffers[1].BufferType == SECBUFFER_EXTRA)
		{
			auto x = InBuffers[1].pvBuffer;
				MoveMemory(readBuffer,
					readBuffer + (readBufferBytes - InBuffers[1].cbBuffer),
					InBuffers[1].cbBuffer);
			readBufferBytes = InBuffers[1].cbBuffer;
		}
		else
		{
			readBufferBytes = 0;
		}
	}
	DebugHresult("Exit ActualSSPINegotiateLoop", scRet);
	return scRet;
}

HRESULT CSSLClient::Disconnect(bool closeUnderlyingSocket)
{
	if (m_hContext)
	{
		HRESULT hr = DisconnectSSL();
		if FAILED(hr)
			return hr;
	}
	return closeUnderlyingSocket ? m_SocketStream->Disconnect() : S_OK;
}

HRESULT CSSLClient::DisconnectSSL()
{
	DWORD           dwType = SCHANNEL_SHUTDOWN;
	PBYTE           pbMessage;
	DWORD           cbMessage;

	SecBufferDesc   OutBuffer;
	SecBuffer       OutBuffers[1];
	DWORD           dwSSPIFlags;
	TimeStamp       tsExpiry;
	DWORD           Status;

	//
	// Notify schannel that we are about to close the connection.
	//

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

	dwSSPIFlags = ISC_REQ_SEQUENCE_DETECT |
		ISC_REQ_REPLAY_DETECT |
		ISC_REQ_CONFIDENTIALITY |
		ISC_RET_EXTENDED_ERROR |
		ISC_REQ_ALLOCATE_MEMORY |
		ISC_REQ_STREAM;

	OutBuffers[0].pvBuffer = nullptr;
	OutBuffers[0].BufferType = SECBUFFER_TOKEN;
	OutBuffers[0].cbBuffer = 0;

	OutBuffer.cBuffers = 1;
	OutBuffer.pBuffers = OutBuffers;
	OutBuffer.ulVersion = SECBUFFER_VERSION;

	Status = g_pSSPI->InitializeSecurityContext(
		m_ClientCreds.getunsaferef(),	// Which certificate to use, already established
		m_hContext.getunsaferef(),		// The context handle
		nullptr,
		dwSSPIFlags,
		0,
		SECURITY_NATIVE_DREP,
		&OutBuffer,
		0,
		nullptr,
		&OutBuffer,
		&dwSSPIFlags,
		&tsExpiry);

	DebugHresult("InitializeSecurityContext initial call", Status);

	// We expect SEC_E_OK here, though in theory it could return SEC_I_CONTEXTEXPIRED or even
	// SEC_I_CONTINUE_NEEDED to indicate that additional shutdown messages are needed. However
	// we know SSL shuts down with a single message so it is ok just to expect SEC_E_OK.

	if (FAILED(Status))
		return Status;

	pbMessage = (PBYTE)OutBuffers[0].pvBuffer;
	cbMessage = OutBuffers[0].cbBuffer;


	//
	// Send the close notify message to the server.
	//

	if (pbMessage != nullptr && cbMessage != 0)
	{
		const DWORD cbData = m_SocketStream->Send(pbMessage, cbMessage);
		if (cbData == SOCKET_ERROR || cbData == 0)
		{
			Status = WSAGetLastError();
			DebugMsg("**** Error %d sending close notify", Status);
			return Status;
		}

		DebugMsg("Sending Close Notify. %d bytes of data sent", cbData);
		if (true)
		{
			PrintFullHexDump(cbData, pbMessage);
			DebugMsg("\n");
		}

		// Free output buffer.
		g_pSSPI->FreeContextBuffer(pbMessage);
	}

	return Status;
}

bool CSSLClient::getServerCertNameMatches() const
{
	return ServerCertNameMatches;
}

bool CSSLClient::getServerCertTrusted() const
{
	return ServerCertTrusted;
}

SECURITY_STATUS CSSLClient::GetNewClientCredentials()
{
	CredentialHandle hCreds;
	SecPkgContext_IssuerListInfoEx IssuerListInfo;
	SECURITY_STATUS Status;

	//
	// Read list of trusted issuers from schannel.
	// 
	// Note the a server will NOT send an issuer list if it has the registry key
	// HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL
	// has a DWORD value called SendTrustedIssuerList set to 0
	//

	Status = g_pSSPI->QueryContextAttributes(m_hContext.getunsaferef(),
		SECPKG_ATTR_ISSUER_LIST_EX,
		(PVOID)&IssuerListInfo);
	if (Status != SEC_E_OK)
	{
		DebugMsg("Error 0x%08x querying issuer list info", Status);
		return Status;
	}

	DebugMsg("Issuer list information returned, issuers = %d", IssuerListInfo.cIssuers);

	// Now go ask for the client credentials
	PCCERT_CONTEXT pCertContext = nullptr;
	CertContextHandle hCertContext;

	if (SelectClientCertificate)
		Status = SelectClientCertificate(pCertContext, &IssuerListInfo, true);
	if (FAILED(Status))
	{
		DebugHresult("Error selecting client certificate", Status);
		return Status;
	}
	hCertContext.attach(pCertContext);
	if (!hCertContext)
		DebugMsg("No suitable client certificate is available to return to the server");
	else
		DebugMsg("Returning client certificate to the server, %S", GetCertName(pCertContext).c_str());

	Status = CreateCredentialsFromCertificate(hCreds.set(), hCertContext.get());

	if (SUCCEEDED(Status) && hCreds)
	{
		// Store the new ones
		m_ClientCreds = std::move(hCreds);
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
	DebugMsg("In CreateCredentialsFromCertificate, certificate %S", GetCertName(pCertContext).c_str());
	// Build Schannel credential structure.

	TLS_PARAMETERS Tlsp = { 0 };
	// Always allow TLS1.2, only allow TLS1.3+ in Windows 11 or greater. Made more complex by the fact this is a list of protocols NOT to use
	Tlsp.grbitDisabledProtocols = SP_PROT_SSL2 | SP_PROT_SSL3 | SP_PROT_TLS1_0 | SP_PROT_TLS1_1; // All protocols prior to TLS 1.2 disabled
	if (!IsWindows11OrGreater()) // Microsoft say TLS 1.3 is not supported prior to Windows 11 / Server 2022 so do not use it
		Tlsp.grbitDisabledProtocols |= SP_PROT_TLS1_3PLUS;
	
	SCH_CREDENTIALS Schc = { 0 };
	Schc.dwVersion = SCH_CREDENTIALS_VERSION;
	if (pCertContext)
	{
		Schc.cCreds = 1;
		Schc.paCred = &pCertContext;
	}
	Schc.dwFlags = SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS | SCH_USE_STRONG_CRYPTO;
	Schc.cTlsParameters = 1;
	Schc.pTlsParameters = &Tlsp;


	SECURITY_STATUS Status;
	TimeStamp       tsExpiry;
	// Get a handle to the SSPI credential
	Status = g_pSSPI->AcquireCredentialsHandle(
		nullptr,                   // Name of principal
		const_cast<WCHAR*>(UNISP_NAME), // Name of package
		SECPKG_CRED_OUTBOUND,   // Flags indicating use
		nullptr,                   // Pointer to logon ID
		&Schc,                  // Package specific data
		nullptr,                   // Pointer to GetKey() func
		nullptr,                   // Value to pass to GetKey()
		phCreds,                // (out) Cred Handle
		&tsExpiry);             // (out) Lifetime (optional)

	DebugHresult("In CreateCredentialsFromCertificate, AcquireCredentialsHandle call", Status);

	if (Status != SEC_E_OK)
	{
		DWORD dw = ::GetLastError();
		if (Status == SEC_E_UNKNOWN_CREDENTIALS)
			DebugMsg("**** Error: 'Unknown Credentials' returned by AcquireCredentialsHandle. LastError=%d", dw);
		return Status;
	}

	return SEC_E_OK;
}
void CSSLClient::SetRecvTimeoutSeconds(int NewRecvTimeoutSeconds, bool NewTimerAutomatic)
{
	m_SocketStream->SetRecvTimeoutSeconds(NewRecvTimeoutSeconds, NewTimerAutomatic);
}

int CSSLClient::GetRecvTimeoutSeconds() const
{
	return m_SocketStream->GetRecvTimeoutSeconds();
}

void CSSLClient::SetSendTimeoutSeconds(int NewSendTimeoutSeconds, bool NewTimerAutomatic)
{
	m_SocketStream->SetSendTimeoutSeconds(NewSendTimeoutSeconds, NewTimerAutomatic);
}

int CSSLClient::GetSendTimeoutSeconds() const
{
	return m_SocketStream->GetSendTimeoutSeconds();
}

void CSSLClient::StartRecvTimer()
{
	m_SocketStream->StartRecvTimer();
}

void CSSLClient::StartSendTimer()
{
	m_SocketStream->StartSendTimer();
}
