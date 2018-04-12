using System;
using System.IO;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	/// <summary>
	/// Represents a <strong>BIT_STRING</strong> ASN.1 tag object.
	/// </summary>
	public sealed class Asn1BitString : UniversalTagBase {
		const Byte tag = (Byte)Asn1Type.BIT_STRING;

		/// <summary>
		/// Initializes a new instance of the <strong>Asn1BitString</strong> class from an existing <see cref="Asn1Reader"/>
		/// class instance.
		/// </summary>
		/// <param name="asn">Existing <see cref="Asn1Reader"/> class instance.</param>
		/// <exception cref="InvalidDataException">
		/// Current position in the <strong>ASN.1</strong> object is not <strong>BIT_STRING</strong>.
		/// </exception>
		public Asn1BitString(Asn1Reader asn)
			: base(asn) {
			if (asn.Tag != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Bit String"));
			}
			UnusedBits = asn.RawData[asn.PayloadStartOffset];
			Value = asn.GetPayload().Skip(1).ToArray();
		}
		/// <summary>
		/// Initializes a new instance of <strong>Asn1BitString</strong> from a ASN.1-encoded byte array.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		/// <exception cref="InvalidDataException">
		/// Byte array in the <strong>rawData</strong> is not valid <strong>BIT_STRING</strong> structure.
		/// </exception>
		public Asn1BitString(Byte[] rawData)
			: base(rawData) {
			if (rawData[0] != tag) {
				throw new InvalidDataException(String.Format(InvalidType, "Bit String"));
			}
			Asn1Reader asn = new Asn1Reader(RawData);
			UnusedBits = asn.RawData[asn.PayloadStartOffset];
			Value = asn.GetPayload().Skip(1).ToArray();
		}
		///  <summary>
		///  Initializes a new instance of <strong>Asn1BitString</strong> from a raw byte array to encode and parameter that indicates
		///  whether the bit length is decremented to exclude trailing zero bits.
		///  </summary>
		///  <param name="valueToEncode">Raw value to encode.</param>
		///  <param name="calculateUnusedBits">
		/// 		<strong>True</strong> if the bit length is decremented to exclude trailing zero bits. Otherwise <strong>False</strong>.
		///  </param>
		/// <exception cref="ArgumentNullException"><strong>valueToEncode</strong> parameter is null reference.</exception>
		public Asn1BitString(Byte[] valueToEncode, Boolean calculateUnusedBits) {
			if (RawData == null) { throw new ArgumentNullException("valueToEncode"); }
			m_encode(valueToEncode, calculateUnusedBits);
		}

		/// <summary>
		/// Gets expicit <strong>BIT_STRING</strong> value (excluding header and <strong>unusedBits</strong> field.
		/// </summary>
		public Byte[] Value { get; private set; }
		/// <summary>
		/// Gets the count of unused bits in the current <strong>BIT_STRING</strong>.
		/// </summary>
		public Byte UnusedBits { get; private set; }

		void m_encode(Byte[] value, Boolean calc) {
			Value = value;
			UnusedBits = (Byte)(calc
				? CalculateUnusedBits(value)
				: 0);
			Byte[] v = new Byte[value.Length + 1];
			v[0] = UnusedBits;
			value.CopyTo(v, 1);
			Init(new Asn1Reader(Asn1Utils.Encode(v, tag)));

		}

		/// <summary>
		/// Gets formatted tag value.
		/// </summary>
		/// <returns>Formatted tag value.</returns>
		public override String GetDisplayValue() {
			StringBuilder SB = new StringBuilder();
			SB.AppendFormat("Unused bits={0}\r\n", UnusedBits);
			String tempString = AsnFormatter.BinaryToString(Value, EncodingType.HexAddress);
			SB.AppendFormat("{0}\r\n", tempString.Replace("\r\n", "\r\n    ").TrimEnd());
			return SB.ToString();
		}

		/// <summary>
		/// Calculates the number of bits left unused in the final byte of content.
		/// </summary>
		/// <param name="bytes">A byte array to process.</param>
		/// <returns>The number of unused bits.</returns>
		/// <exception cref="ArgumentNullException"><strong>bytes</strong> paramter is null reference.</exception>
		public static Byte CalculateUnusedBits(Byte[] bytes) {
			if (bytes == null) { throw new ArgumentNullException("bytes"); }
			return CalculateUnusedBits(bytes[bytes.Length - 1]);
		}
		/// <summary>
		/// Calculates the number of bits left unused in the specified byte.
		/// </summary>
		/// <param name="b">The final byte of content</param>
		/// <returns>The number of unused bits.</returns>
		public static Byte CalculateUnusedBits(Byte b) {
			Byte unused = 0;
			Byte mask = 1;
			while ((mask & b) == 0 && mask < 128) {
				unused++;
				mask <<= 1;
			}
			return unused;
		}
	}
}
