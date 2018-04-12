using SwitchLink.Cryptography.RSACryptography.Models.Asn1.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	sealed class Asn1UTF8String : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.UTF8String;

		public Asn1UTF8String(String inputString) {
			m_encode(inputString);
		}
		public Asn1UTF8String(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "UTF-8 String"));
			}
			m_decode(asn);
		}
		public Asn1UTF8String(Byte[] rawData) : base(rawData) {
			m_decode(new Asn1Reader(rawData));
		}

		public String Value { get; private set; }

		void m_encode(String inputString) {
			if (!testValue(inputString)) {
				throw new InvalidDataException(String.Format(InvalidType, "UTF-8 String"));
			}
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.ASCII.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			if (!testValue(asn.GetPayload())) {
				throw new InvalidDataException(String.Format(InvalidType, "UTF-8 String"));
			}
			Value = Encoding.ASCII.GetString(asn.GetPayload());
		}
		static Boolean testValue(String str) {
			try {
				foreach (Char c in str) {
					Convert.ToByte(c);
				}
				return true;
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
