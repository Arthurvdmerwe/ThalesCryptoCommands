﻿using System;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1
{
	[Flags]
	public enum EncodingFormat : uint {
		/// <summary>
		/// Appends a carriage return/line feed (CR/LF) pair (0x0D/0x0A) to the ecncoded string.
		/// </summary>
		CRLF = 0,
		/// <summary>
		/// Do not append any new line characters to the encoded string. The default behavior is to use a carriage return/line
		/// feed (CR/LF) pair (0x0D/0x0A) to represent a new line.
		/// <para><strong>Windows Server 2003 and Windows XP:</strong> This value is not supported.</para>
		/// </summary>
		NOCRLF = 0x40000000,
		/// <summary>
		/// Only use the line feed (LF) character (0x0A) for a new line. The default behavior is to use a CR/LF pair
		/// (0x0D/0x0A) to represent a new line.
		/// </summary>
		NOCR = 0x80000000
	}
}