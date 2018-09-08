#pragma once

class CSSLHelper
{
private:
	const byte * const OriginalBufPtr;
	const byte * DataPtr; // Points to data inside message
	const byte * BufEnd;
	const int MaxBufBytes;
	UINT8 contentType, major, minor;
	UINT16 length;
	UINT8 handshakeType;
	UINT16 handshakeLength;
	bool CanDecode();
	bool decoded;
public:
	CSSLHelper(const byte * BufPtr, const int BufBytes);
	~CSSLHelper();
	// Max length of handshake data buffer
	void TraceHandshake();
	// Is this packet a complete client initialize packet
	bool IsClientInitialize();
	// Get SNI provided hostname
	CString GetSNI();
};
