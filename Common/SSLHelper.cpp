#include "pch.h"
#include <string>
#include "SSLHelper.h"
#include "Utilities.h"

// General purpose helper class for SSL, decodes buffers for diagnostics, handles SNI

CSSLHelper::CSSLHelper(const byte *BufPtr, const int BufBytes) :
	OriginalBufPtr(BufPtr),
	DataPtr(BufPtr),
	MaxBufBytes(BufBytes)
{
	decoded = BufPtr && CanDecode();
}

std::string getTlsVersionText(int major, int minor)
{
	if (major == 3)
	{
		if (minor == 0)
			return "SSL 3.0";
		else if (minor == 1)
			return "TLS 1.0";
		else if (minor == 2)
			return "TLS 1.1";
		else if (minor == 3)
			return "TLS 1.2";
		else if (minor == 4)
			return "TLS 1.3";
		else
			return "TLS 1.3+";
	}
	return "";
}


// Decode a buffer
bool CSSLHelper::CanDecode()
{
	if (MaxBufBytes < 5)
		return false;
	else
	{
		contentType = *(DataPtr++);
		major = *(DataPtr++);
		minor = *(DataPtr++);
		length = (*(DataPtr) << 8) + *(DataPtr + 1);
		DataPtr += 2;
		if (length + 5 > MaxBufBytes)
			return false;
		// This is a version we recognize
		if (contentType != 22)
			return false;
		// This is a handshake message (content type 22)
		handshakeType = *(DataPtr++);
		handshakeLength = (*DataPtr << 16) + (*(DataPtr + 1) << 8) + *(DataPtr + 2);
		DataPtr += 3;
		if (handshakeType != 1)
			return false;
		BufEnd = OriginalBufPtr + 5 + 4 + handshakeLength;
		return true;
	}
}

// Trace handshake buffer
void CSSLHelper::TraceHandshake()
{
	TracePacket(OriginalBufPtr, MaxBufBytes);
}

// Trace an SSL buffer (static method)
int CSSLHelper::TracePacket(const void* const Ptr, const int MaxBufBytes)
{
	const byte *BufPtr = (const byte*)Ptr;
	const byte *const OriginalBufPtr = BufPtr;
	const byte *BufEnd = OriginalBufPtr + MaxBufBytes; // starts out as end of buffer, finishes up as end of packet
	UINT8 contentType = 0, major = 0, minor = 0;
	UINT16 length = 0;
	bool FormatRecognized = true;
	int ExtraBytes = -1;
	int TracedBytes = 0;

	auto nextItem = [&](int itemSize, bool skipItem, bool checkLength)
		{
			if (BufEnd - BufPtr < itemSize)
				throw std::exception("Buffer too small to contain item size");
			int accum = 0;
			for (int i = 0; i < itemSize; i++)
			{
				accum = (accum << 8) + *BufPtr;
				BufPtr++;
			}
			if (checkLength && (BufEnd - BufPtr < accum))
				throw std::exception("Buffer too small for item content");
			if (skipItem) // Assume this is a self-exclusive length, so move the pointer past the data
				BufPtr += accum;
			return accum;
		};

	auto skipNextItem = [&nextItem](int itemSize)
		{return nextItem(itemSize, true, true); };

	auto getNextItemLength = [&nextItem](int itemSize)
		{return nextItem(itemSize, false, true); };

	auto getNextItemValue = [&nextItem](int itemSize)
		{return nextItem(itemSize, false, false); };

	if (MaxBufBytes < 5)
		DebugMsg("Buffer space too small (under 5 bytes) to contain a TLS message");
	else
	{
		contentType = getNextItemValue(1);
		major = getNextItemValue(1);
		minor = getNextItemValue(1);
		length = getNextItemValue(2);


		// Start Packet analysis code

		FormatRecognized = false;
		if (contentType > 50 || major > 9 || length > 10000 || contentType == 0 || major == 0 || length == 0)
			DebugMsg("This does not look like a TLS packet");
		else if (major == 3)
		{
			FormatRecognized = true;
			BufEnd = BufPtr + length;
			DebugMsg("New Packet: Content Type = %d, legacy version %d.%d (%s), length = 5+%d, buffer length = %d ", contentType, major, minor, getTlsVersionText(major, minor).c_str(), length, MaxBufBytes);
		}
		else
		{
			DebugMsg("Content Type = %d, Major.Minor Version = %d.%d, length %d (0x%04X)", contentType, major, minor, length, length);
			DebugMsg("This TLS version is not recognized so no more information is available");
		}

		if (FormatRecognized)
		{
			ExtraBytes = MaxBufBytes - 5 - length;
			if (ExtraBytes == 0)
				TracedBytes = MaxBufBytes; //  Exactly one buffer is present, no need to print anything
			else if (ExtraBytes > 0)
			{
				TracedBytes = length + 5;
				DebugMsg("A complete packet + %d extra bytes are present, extra bytes%s", ExtraBytes, HexDigits(OriginalBufPtr + TracedBytes, min(16, MaxBufBytes - TracedBytes)).c_str());
			}
			else // extraBytes < 0
			{
				DebugMsg("Only part of the buffer is present, %d more bytes are needed", -ExtraBytes);
				// Leave TracedBytes at 0;
			}
		}
		else
			PrintHexDump(MaxBufBytes, OriginalBufPtr);

		if (FormatRecognized && contentType != 22)
		{
			switch (contentType)
			{
			case 20: DebugMsg("Content type 20 = Change Cipher Spec, length = %d", length + 5); break;
			case 21: DebugMsg("Content type 21 = Alert, length = %d", length + 5); break;
			case 22: DebugMsg("Content type 22 = Handshake, length = %d", length + 5); break;
			case 23: DebugMsg("Content type 23 = Application Data, length = %d", length + 5); break;
			default: DebugMsg("This content type (%d) is not recognized, length = %d", contentType, length + 5); break;
			}
			FormatRecognized = false;
		}
		// If it is recognized this must be a handshake message (content type 22)
		if (FormatRecognized && contentType == 22)
		{
			int handshakeType = getNextItemValue(1);
			int handshakeLength = getNextItemLength(3);
			DebugMsg("Content type 22 = Handshake message, handshake type %d, handshake length = %d", handshakeType, handshakeLength);
			if (handshakeType == 1 || handshakeType == 2)
			{
				try
				{
					if (handshakeType == 1)
						DebugMsg("Handshake type = client hello");
					else
						DebugMsg("Handshake type = server hello");
					if (BufEnd - BufPtr < 2 + 4 + 28)
						DebugMsg("Handshake buffer too short for fixed fields");
					else
					{
						int ClientMajorVersion = getNextItemValue(1);
						int ClientMinorVersion = getNextItemValue(1);
						DebugMsg("Handshake version field = %d.%d (%s)", ClientMajorVersion, ClientMinorVersion, getTlsVersionText(ClientMajorVersion, ClientMinorVersion).c_str());
						BufPtr += 4; // Skip Time
						BufPtr += 28; // Skip Random bytes
					}
					int sessionidLength = skipNextItem(1);
					if (handshakeType == 1) // Client hello
					{
						int cipherSuitesLength = skipNextItem(2);
						int compressionMethodsLength = skipNextItem(1);
						DebugMsg("Client Handshake buffer: sessionidLength = %d, cipherSuitesLength = %d, compressionMethodsLength = %d", sessionidLength, cipherSuitesLength, compressionMethodsLength);
					}
					else // Server Hello
					{
						int cipherSuite = getNextItemValue(2);
						int compressionMethod = getNextItemValue(1);
						DebugMsg("Server Handshake buffer: sessionidLength = %d, cipherSuite = %d, compressionMethod = %d", sessionidLength, cipherSuite, compressionMethod);
					}
					//bool extensionsPresent = BufPtr < BufEnd;
					UINT16 extensionsTotalLength = getNextItemLength(2); // Number of bytes of extension data
					int unusedBytes = BufEnd - BufPtr - extensionsTotalLength; // Available space after data
					if (unusedBytes == 0)
					{
						if (extensionsTotalLength == 0)
							DebugMsg("There is no extension data");
						else
							DebugMsg("There are %d bytes of extension data as follows, see IANA definitions for extension details", extensionsTotalLength);
					}
					else if (unusedBytes > 0)
					{
						if (extensionsTotalLength == 0)
							DebugMsg("There is no extension data but there are %d bytes of unused data", unusedBytes);
						else
							DebugMsg("There are %d bytes of extension data followed by %d bytes of unused space, see IANA definitions for extension details", extensionsTotalLength, unusedBytes);
					}
					else // (extensionsDelta < 0)
						throw std::exception("There is insufficient space for the extension data, overshot by %d bytes", -unusedBytes);

					bool firstUnreconizedExtension = true;
					
					while (BufPtr - OriginalBufPtr <= length)
					{
						UINT16 extensionType = getNextItemValue(2);
						UINT16 extensionDataLength = getNextItemLength(2);
						if (extensionDataLength > BufEnd - BufPtr) // Something's wrong, the extension overflows the buffer just give up
						{
							DebugMsg("Extension length is %d which overflows the packet, something is wrong, abandoning extension analysis, remaining extension block is", extensionDataLength);
							BufPtr -= 4;
							extensionDataLength = BufEnd - BufPtr;
							PrintHexDump(extensionsTotalLength, BufPtr);
						}
						else if (extensionType == 0) // server name list, in practice there's only ever one name in it (see RFC 6066)
						{
							UINT16 serverNameListLength = getNextItemLength(2);
							DebugMsg("Extension Type %d (Server name list), length %d", extensionType, serverNameListLength);
							const byte *serverNameListEnd = BufPtr + serverNameListLength;
							while (BufPtr < serverNameListEnd)
							{
								UINT8 serverNameType = getNextItemValue(1);
								UINT16 serverNameLength = getNextItemLength(2);
								if (serverNameType == 0)
								{
									DebugBeginMsg();
									DebugEndMsg("   Requested name \"%*s\"", serverNameLength, BufPtr);
								}
								else
									DebugMsg("   Server name Type %d, length %d, data \"%*s\"", serverNameType, serverNameLength, serverNameLength, BufPtr);
								BufPtr += serverNameLength;
							}
						}
						else if (extensionType == 43 && extensionDataLength == 2) // TLS Version, length 2 is a simple one
						{
							int major = getNextItemValue(1);
							int minor = getNextItemValue(1);
							DebugMsg("Extension type 43 = TLS Version, value = %d.%d (%s)", major, minor, getTlsVersionText(major, minor).c_str());
						}
						else if (extensionType == 65281 && extensionDataLength == 1) // 0xff01 TLS Renegotiation extension, length 1 is a simple one
							DebugMsg("Extension type 65281 = TLS Renegotiation, value = %d", getNextItemValue(1));
						else
						{
							bool unrecognized = false;
							switch (extensionType)
							{
							case 00: DebugBeginMsg("Extension type 00 = Server Name"); break;
							case 01: DebugBeginMsg("Extension type 01 = Max Fragment length"); break; // For completeness, should have already been handled
							case 02: DebugBeginMsg("Extension type 02 = Client Certificate URL"); break;
							case 03: DebugBeginMsg("Extension type 03 = Trusted CA keys"); break;
							case 04: DebugBeginMsg("Extension type 04 = Truncated MAC"); break;
							case 05: DebugBeginMsg("Extension type 05 = Status request"); break;
							case 23: DebugBeginMsg("Extension type 23 = Extended Master Secret"); break;
							default: unrecognized = true; break;
							}
							if (unrecognized)
							{
								if (firstUnreconizedExtension)
								{
									DebugMsg("Some extensions are unrecognized, this is a dump beginning at the first one:");
									PrintFullHexDump(BufEnd - BufPtr + 4, BufPtr-4);
									firstUnreconizedExtension = false;
								}
								DebugBeginMsg("Extension Type %d has length %d", extensionType, extensionDataLength);
							}
							if (extensionDataLength == 0)
								DebugEndMsg();
							else if (extensionDataLength > 16)
							{
								DebugEndMsg(", data is:");
								PrintFullHexDump(extensionDataLength, BufPtr);
							}
							else if (extensionDataLength > 0)
								DebugEndMsg("%s", HexDigits(BufPtr, extensionDataLength).c_str());
							BufPtr += extensionDataLength;
						}
					}
				}
				catch (const std::exception& e)
				{
					DebugMsg("*** Faulted analyzing packet contents at offset %d: %s***", BufPtr -OriginalBufPtr, e.what());
				}
				int Unused = BufEnd - BufPtr;
				if (Unused == 0)
					; // Extensions exactly filled the header, not worth mentioning
				else if (Unused > 0)
				{
					DebugMsg("Space after extensions is %d bytes", Unused);
					PrintHexDump(Unused, BufPtr);
				}
				else
					DebugMsg("** Error ** Extensions overflow the packet by %d bytes", -Unused);
			}
			else
			{
				switch (handshakeType)
				{
				case  0: DebugMsg("Handshake type 00 = Hello Request"); break;
				case  1: DebugMsg("Handshake type 01 = Client Hello"); break; // For completeness, should have already been handled
				case  2: DebugMsg("Handshake type 02 = Server hello"); break;
				case  3: DebugMsg("Handshake type 03 = Hello Request"); break;
				case  4: DebugMsg("Handshake type 04 = New Session Ticket"); break; // For completeness, should have already been handled
				case  5: DebugMsg("Handshake type 05 = End of Early Data"); break;
				case  8: DebugMsg("Handshake type 08 = encrypted extensions"); break;
				case 11: DebugMsg("Handshake type 11 = Certificate"); break;
				case 12: DebugMsg("Handshake type 12 = Server key Exchange"); break;
				case 13: DebugMsg("Handshake type 13 = Certificate request"); break;
				case 14: DebugMsg("Handshake type 14 = Server Hello Done"); break;
				case 15: DebugMsg("Handshake type 15 = Certificate Verify"); break;
				case 16: DebugMsg("Handshake type 16 = Client key Exchange"); break;
				case 20: DebugMsg("Handshake type 20 = Finished"); break;
				case 21: DebugMsg("Handshake type 21 = Certificate URL"); break;
				case 22: DebugMsg("Handshake type 22 = Certificate Status"); break;
				default: DebugMsg("Handshake type (%d) is not recognized", handshakeType); break;
				}
			}
		}
	}
	if (ExtraBytes > 0) // we recognized at least enough of the format to decode a length and we know there's more data
	{
		DebugMsg("");
		DebugMsg("Analyzing Concatenated Data");
		TracePacket(OriginalBufPtr + 5 + length, MaxBufBytes - 5 - length);
	}
	return TracedBytes;
}

// Is this packet a complete client initialize packet
bool CSSLHelper::IsClientInitialize() const
{
	return decoded;
}

// Get SNI provided hostname
std::wstring CSSLHelper::GetSNI() const
{
	const byte * BufPtr = DataPtr;
	if (decoded)
	{
		// This is a client hello message (handshake type 1)
		BufPtr += 2; // Skip ClientVersion
		BufPtr += 32; // Skip Random
		UINT8 sessionidLength = *BufPtr;
		BufPtr += 1 + sessionidLength; // Skip SessionID
		UINT16 cipherSuitesLength = (*(BufPtr) << 8) + *(BufPtr + 1);
		BufPtr += 2 + cipherSuitesLength; // Skip CipherSuites
		UINT8 compressionMethodsLength = *BufPtr;
		BufPtr += 1 + compressionMethodsLength; // Skip Compression methods
		//bool extensionsPresent = BufPtr < BufEnd;
		//UINT16 extensionsLength = (*(BufPtr) << 8) + *(BufPtr + 1);
		BufPtr += 2;
		while (BufPtr < BufEnd)
		{
			UINT16 extensionType = (*(BufPtr) << 8) + *(BufPtr + 1);
			BufPtr += 2;
			UINT16 extensionDataLength = (*(BufPtr) << 8) + *(BufPtr + 1);
			BufPtr += 2;
			if (extensionType == 0) // server name list, in practice there's only ever one name in it (see RFC 6066)
			{
				UINT16 serverNameListLength = (*(BufPtr) << 8) + *(BufPtr + 1);
				BufPtr += 2;
				const byte *serverNameListEnd = BufPtr + serverNameListLength;
				while (BufPtr < serverNameListEnd)
				{
					UINT8 serverNameType = *(BufPtr++);
					UINT16 serverNameLength = (*(BufPtr) << 8) + *(BufPtr + 1);
					BufPtr += 2;
					if (serverNameType == 0)
					{
						CString s((char*)BufPtr, serverNameLength); // Convert utf8 to utf16
						return s.GetBuffer();
					}
					BufPtr += serverNameLength;
				}
			}
			else
			{
				BufPtr += extensionDataLength;
			}
		}
	}
	return std::wstring();
}
