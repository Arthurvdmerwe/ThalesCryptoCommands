using SwitchLink.Cryptography.RSACryptography.Models.Asn1.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	sealed class Asn1PrintableString : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.PrintableString;

		public Asn1PrintableString(String inputString) {
			m_encode(inputString);
		}
		public Asn1PrintableString(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Printable String"));
			}
			m_decode(asn);
		}
		public Asn1PrintableString(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public String Value { get; private set; }

		void m_encode(String inputString) {
			if (!testValue(inputString)) {
				throw new InvalidDataException(String.Format(InvalidType, "Printable String"));
			}
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			if (!testValue(asn.GetPayload())) {
				throw new InvalidDataException(String.Format(InvalidType, "Printable String"));
			}
			Value = Encoding.ASCII.GetString(asn.GetPayload());
		}
		static Boolean testValue(String str) {
			List<Byte> alphabet = StringUtils.GetAlphabet((Asn1Type)tag);
			try {
				return str.All(c => alphabet.Contains(Convert.ToByte(c)));
			} catch { return false; }
		}
		static Boolean testValue(IEnumerable<Byte> rawData) {
			List<Byte> alphabet = StringUtils.GetAlphabet((Asn1Type)tag);
			return rawData.All(alphabet.Contains);
		}

		public override String GetDisplayValue() {
			return Value;
		}
	}
}
