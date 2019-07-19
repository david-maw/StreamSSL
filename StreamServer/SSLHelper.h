#pragma once

class CSSLHelper
{
private:
	const byte * const OriginalBufPtr;
	const byte * DataPtr; // Points to data inside message
	const byte* BufEnd = nullptr;
	const int MaxBufBytes;
	UINT8 contentType = 0, major = 0, minor = 0;
	UINT16 length = 0;
	UINT8 handshakeType = 0;
	UINT16 handshakeLength = 0;
	bool CanDecode();
	bool decoded;
public:
	CSSLHelper(const byte * BufPtr, const int BufBytes);
	~CSSLHelper() = default;
	// Max length of handshake data buffer
	void TraceHandshake();
	// Is this packet a complete client initialize packet
	bool IsClientInitialize() const;
	// Get SNI provided hostname
	std::wstring GetSNI() const;
};
