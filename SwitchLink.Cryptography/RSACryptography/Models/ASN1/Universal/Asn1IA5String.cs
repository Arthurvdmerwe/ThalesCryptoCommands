using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	sealed class Asn1IA5String : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.IA5String;

		public Asn1IA5String(String inputString) {
			m_encode(inputString);
		}
		public Asn1IA5String(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "IA5 String"));
			}
			m_decode(asn);
		}
		public Asn1IA5String(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public String Value { get; private set; }

		void m_encode(String inputString) {
			if (inputString.Any(c => c > 127)) {
				throw new InvalidDataException(String.Format(InvalidType, "IA5 String"));
			}
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			if (asn.GetPayload().Any(b => b > 127)) {
				throw new InvalidDataException(String.Format(InvalidType, "IA5 String"));
			}
			Value = Encoding.ASCII.GetString(asn.GetPayload());
		}
		
		public override String GetDisplayValue() {
			return Value;
		}
	}
}
