using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	sealed class Asn1VisibleString : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.VisibleString;

		public Asn1VisibleString(String inputString) {
			m_encode(inputString);
		}
		public Asn1VisibleString(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Visible String"));
			}
			m_decode(asn);
		}
		public Asn1VisibleString(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public String Value { get; private set; }

		void m_encode(String inputString) {
			if (inputString.Any(c => c < 32 || c > 126)) {
				throw new InvalidDataException(String.Format(InvalidType, "Visible String"));
			}
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			if (asn.GetPayload().Any(b => b < 32 || b > 126)) {
				throw new InvalidDataException(String.Format(InvalidType, "Visible String"));
			}
			Value = Encoding.ASCII.GetString(asn.GetPayload());
		}
		
		public override String GetDisplayValue() {
			return Value;
		}
	}
}
