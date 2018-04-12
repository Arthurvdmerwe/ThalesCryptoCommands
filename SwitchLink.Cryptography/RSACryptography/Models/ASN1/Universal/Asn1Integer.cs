using System;
using System.IO;
using System.Linq;
using SwitchLink.Cryptography.RSACryptography.Models.Asn1.CLRExtensions;
using Org.BouncyCastle.Math;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	public sealed class Asn1Integer : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.INTEGER;

		public Asn1Integer(BigInteger inputInteger) {
			m_encode(inputInteger);
		}
		public Asn1Integer(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "INTEGER"));
			}
			m_decode(asn);
		}
		public Asn1Integer(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public BigInteger Value { get; private set; }
		public static Boolean DecodeIntegerAsInteger { get; set; }

		void m_encode(BigInteger inputInteger) {
			Value = inputInteger;
			Init(new Asn1Reader(Asn1Utils.Encode(inputInteger.GetAsnBytes(), tag)));
		}
		void m_decode(Asn1Reader asn) {
			Value = new BigInteger(asn.GetPayload().Reverse().ToArray());
		}
	}
}
