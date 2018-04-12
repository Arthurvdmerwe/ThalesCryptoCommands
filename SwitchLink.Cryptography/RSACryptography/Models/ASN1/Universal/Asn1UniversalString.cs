using System;
using System.IO;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	sealed class Asn1UniversalString : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.UniversalString;

		public Asn1UniversalString(String inputString) {
			m_encode(inputString);
		}
		public Asn1UniversalString(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Universal String"));
			}
			m_decode(asn);
		}
		public Asn1UniversalString(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public String Value { get; private set; }

		void m_encode(String inputString) {
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.UTF32.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			Value = Encoding.UTF32.GetString(asn.GetPayload());
		}

		public override String GetDisplayValue() {
			return Value;
		}
	}
}
