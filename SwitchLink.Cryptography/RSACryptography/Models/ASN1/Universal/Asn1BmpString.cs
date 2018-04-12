using System;
using System.IO;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	/// <summary>
	/// Represents a <strong>BMPString</strong> ASN.1 tag object. <Strong>BMPString</Strong> is a 16-bit unicode string where each character
	/// is encoded by using two bytes in Big Endian encoding.
	/// </summary>
	public sealed class Asn1BMPString : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.BMPString;

		/// <summary>
		/// Initializes a new instance of the <strong>Asn1BMPString</strong> class from a unicode string.
		/// </summary>
		/// <param name="inputString">A unicode string to encode.</param>
		public Asn1BMPString(String inputString) {
			m_encode(inputString);
		}
		/// <summary>
		/// Initializes a new instance of the <strong>Asn1BMPString</strong> class from an existing <see cref="Asn1Reader"/>
		/// class instance.
		/// </summary>
		/// <param name="asn">Existing <see cref="Asn1Reader"/> class instance.</param>
		/// <exception cref="InvalidDataException">
		/// Current position in the <strong>ASN.1</strong> object is not <strong>BMPString</strong>.
		/// </exception>
		public Asn1BMPString(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "BMP String"));
			}
			m_decode(asn);
		}
		/// <summary>
		/// Initializes a new instance of <strong>Asn1BMPString</strong> from a ASN.1-encoded byte array.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		/// <exception cref="InvalidDataException">
		/// Byte array in the <strong>rawData</strong> is not valid <strong>BMPString</strong> structure.
		/// </exception>
		public Asn1BMPString(Byte[] rawData) : base(rawData) {
			if (rawData[0] != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Bit String"));
			}
			m_decode(new Asn1Reader(rawData));
		}

		/// <summary>
		/// Gets the decoded <strong>BMPString</strong> value.
		/// </summary>
		public String Value { get; private set; }

		void m_encode(String inputString) {
			Value = inputString;
			Init(new Asn1Reader(Asn1Utils.Encode(Encoding.BigEndianUnicode.GetBytes(inputString), tag)));
		}
		void m_decode(Asn1Reader asn) {
			Value = Encoding.BigEndianUnicode.GetString(asn.GetPayload());
		}

		/// <summary>
		/// Gets formatted tag value.
		/// </summary>
		/// <returns>Formatted tag value.</returns>
		public override String GetDisplayValue() {
			return Value;
		}
	}
}
