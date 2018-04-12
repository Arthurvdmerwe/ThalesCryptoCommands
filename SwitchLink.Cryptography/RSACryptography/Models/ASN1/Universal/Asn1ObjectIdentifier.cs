﻿using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	/// <summary>
	/// Represents ASN.1 Object Identifier type.
	/// </summary>
	public sealed class Asn1ObjectIdentifier : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.OBJECT_IDENTIFIER;
		const String tagName = "Object Identifier";

		/// <summary>
		/// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from a string
		/// that represents object identifier value.
		/// </summary>
		/// <param name="oid">String represents object identifier value.</param>
		/// <exception cref="InvalidDataException">The string is not valid object identifier.</exception>
		/// <exception cref="OverflowException">The string is too large.</exception>
		/// <remarks>Maximum object identifier string is 8kb.</remarks>
		public Asn1ObjectIdentifier(String oid) {
			m_encode(oid);
		}
		/// <summary>
		/// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from an existing
		/// <see cref="Asn1Reader"/> class instance.
		/// </summary>
		/// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents object identifier.</param>
		/// <exception cref="Asn1InvalidTagException">
		/// The current state of <strong>ASN1</strong> object is not object identifier.
		/// </exception>
		public Asn1ObjectIdentifier(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new Asn1InvalidTagException(String.Format(InvalidType, tagName));
			}
			m_decode(asn);
		}
		/// <summary>
		/// Initializes a new instance of the <strong>Asn1ObjectIdentifier</strong> class from a byte array
		/// that represents encoded object identifier.
		/// </summary>
		/// <param name="rawData">Byte array that represents encoded object identifier.</param>
		public Asn1ObjectIdentifier(Byte[] rawData) : base(rawData) {
			if (rawData[0] != tag) {
				throw new Asn1InvalidTagException(String.Format(InvalidType, tagName));
			}
			m_decode(new Asn1Reader(rawData));
		}

		/// <summary>
		/// Gets decoded Object Identifier value.
		/// </summary>
		public Oid Value { get; private set; }

		void m_encode(String oid) {
			if (oid.Length > 8096) { throw new OverflowException("Oid string is longer than 8kb"); }
			List<UInt64> tokens;
			if (!validateOidString(oid, out tokens)) {
				throw new InvalidDataException(String.Format(InvalidType, tagName));
			}
			Value = new Oid(oid);
			Init(new Asn1Reader(Asn1Utils.Encode(encode(tokens), tag)));
		}
		void m_decode(Asn1Reader asn) {
			Value = new Oid(decode(asn.RawData, asn.PayloadStartOffset, asn.PayloadLength));
		}

		static Byte[] encode(IList<UInt64> tokens) {
			List<Byte> rawOid = new List<Byte>();
			for (Int32 token = 0; token < tokens.Count; token++) {
				// first two arcs are encoded in a single byte
				if (token == 0) {
					rawOid.Add((Byte)(40 * tokens[token] + tokens[token + 1]));
					continue;
				}
				if (token == 1) {  continue; }
				Int16 bitLength = 0;
				UInt64 temp = tokens[token];
				// calculate how many bits are occupied by the current integer value
				do {
					temp = (UInt64) Math.Floor((Double)temp / 2);
					bitLength++;
				} while (temp > 0);
				// calculate how many additional bytes are required and encode each integer in a 7 bit.
				// 8th bit of the integer is shifted to the left and 8th bit is set to 1 to indicate that
				// additional bytes are related to the current OID arc. Details:
				// http://msdn.microsoft.com/en-us/library/bb540809(v=vs.85).aspx
				// loop may not execute if arc value is less than 128.
				for (Int32 index = (bitLength - 1) / 7; index > 0; index--) {
					rawOid.Add((Byte)(0x80 | ((tokens[token] >> (index * 7)) & 0x7f)));
				}
				rawOid.Add((Byte)(tokens[token] & 0x7f));
			}
			return rawOid.ToArray();
		}
		static String decode(Byte[] rawBytes) {
			return decode(rawBytes, 0, rawBytes.Length);
		}
		static String decode(IList<Byte> rawBytes, Int32 start, Int32 count) {
			StringBuilder SB = new StringBuilder();
			Int32 token = 0;
			for (Int32 i = start; i < start + count; i++) {
				if (token == 0) {
					SB.Append(rawBytes[i] / 40);
					SB.Append("." + rawBytes[i] % 40);
					token++;
					continue;
				}
				UInt64 value = 0;
				Boolean proceed;
				do {
					value <<= 7;
					value += (UInt64)(rawBytes[i] & 0x7f);
					proceed = (rawBytes[i] & 0x80) > 0;
					if (proceed) {
						token++;
						i++;
					}
				} while (proceed);
				SB.Append("." + value);
				token++;
			}
			return SB.ToString();
		}
		static Boolean validateOidString(String oid, out List<UInt64> tokens) {
			String[] strTokens = oid.Split('.');
			if (strTokens.Length < 3) {
				tokens = null;
				return false;
			}
			tokens = new List<UInt64>();
			for (Int32 index = 0; index < strTokens.Length; index++) {
				try {
					UInt64 value = UInt64.Parse(strTokens[index]);
					if (index == 0 && value > 2) { return false; }
					if (index == 1 && value > 39) { return false; }
					tokens.Add(value);
				}
				catch {
					tokens = null;
					return false;
				}
			}
			return true;
		}

		/// <summary>
		/// Decodes ASN.1-encoded object identifier to an instance of <see cref="Oid"/> class.
		/// </summary>
		/// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents object identifier.</param>
		/// <exception cref="ArgumentNullException">
		/// <strong>asn</strong> parameter is null reference.
		/// </exception>
		/// <exception cref="Asn1InvalidTagException">
		/// The current state of <strong>ASN1</strong> object is not object identifier.
		/// </exception>
		/// <returns>Decoded object identifier.</returns>
		public static Oid Decode(Asn1Reader asn) {
			if (asn == null) { throw new ArgumentNullException("asn"); }
			if (asn.Tag != tag) {
				throw new Asn1InvalidTagException(String.Format(InvalidType, tagName));
			}
			return new Oid(decode(asn.RawData, asn.PayloadStartOffset, asn.PayloadLength));
		}
		///// <summary>
		///// Decodes all the bytes in the specified ASN.1-encoded byte array into a string.
		///// </summary>
		///// <param name="rawBytes">Byte array that represents encoded object identifier.</param>
		///// <returns>Decoded Object Identifier.</returns>
		//public static Oid Decode(Byte[] rawBytes) {
		//	if (rawBytes == null) {
		//		throw new ArgumentNullException("rawBytes");
		//	}
		//	if (rawBytes[0] != tag) {
		//		throw new Asn1InvalidTagException();
		//	}
		//	ASN1 asn = new ASN1(rawBytes);
		//	return new Oid(decode(asn.RawData, asn.PayloadStartOffset, asn.PayloadLength));
		//}

		///// <summary>
		///// Decodes a range of bytes from a byte array into an Object Identifier.
		///// </summary>
		///// <param name="rawBytes">ASN.1-encoded byte array.</param>
		///// <param name="start">The index of the first byte of to decode.</param>
		///// <param name="count">The number of bytes to decode.</param>
		///// <returns>Decoded Object Identifier.</returns>
		//public static Oid Decode(Byte[] rawBytes, Int32 start, Int32 count) {
		//	if (rawBytes == null) {
		//		throw new ArgumentNullException("rawBytes");
		//	}
		//	if (rawBytes[0] != tag) {
		//		throw new Asn1InvalidTagException();
		//	}
		//	if (start < 0 || start > rawBytes.Length) {
		//		start = 0;
		//	}
		//	if (count < 0 || start + count > rawBytes.Length) {
		//		count = rawBytes.Length - start;
		//	}
		//	return new Oid(decode(rawBytes, start, count));
		//}
		/// <summary>
		/// Gets decoded Object Identifier string value.
		/// </summary>
		/// <returns>Decoded Object Identifier string value.</returns>
		public override String GetDisplayValue() {
			return String.IsNullOrEmpty(Value.FriendlyName)
				? Value.Value
				: Value.FriendlyName + " (" + Value.Value + ")";
		}
	}
}
