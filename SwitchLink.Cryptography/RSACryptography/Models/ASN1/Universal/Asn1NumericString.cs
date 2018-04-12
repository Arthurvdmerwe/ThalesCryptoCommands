using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	sealed class Asn1NumericString : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.NumericString;

		public Asn1NumericString(String inputString) {
			m_encode(inputString);
		}
		public Asn1NumericString(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Numeric String"));
			}
			m_decode(asn);
		}
		public Asn1NumericString(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public String Value { get; private set; }

		void m_encode(String inputString) {
			if (inputString.Any(c => (c < 48 || c > 57) && c != 32)) {
				throw new InvalidDataException(String.Format(InvalidType, "Numeric String"));
			}
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			if (asn.GetPayload().Any(b => (b < 48 || b > 57) && b != 32)) {
				throw new InvalidDataException(String.Format(InvalidType, "Numeric String"));
			}
			Value = Encoding.ASCII.GetString(asn.GetPayload());
		}
		
		public override String GetDisplayValue() {
			return Value;
		}
	}
}
