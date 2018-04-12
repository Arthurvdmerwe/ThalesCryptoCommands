using System;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	/// <summary>
	/// Repesents a base class for ASN.1 primitive tag classes. This class provides
	/// </summary>
	public class UniversalTagBase {
		/// <summary>
		/// Initializes a new instance of <strong>UniversalTagBase</strong> class.
		/// </summary>
		protected UniversalTagBase() { }
		/// <summary>
		/// Initializes a new instance of <strong>UniversalTagBase</strong> from an existing <see cref="Asn1Reader"/>
		/// class instance.
		/// </summary>
		/// <param name="asn">Existing <see cref="ArgumentNullException"/> class instance.</param>
		/// <exception cref="Asn1Reader"><strong>asn</strong> parameter is null reference.</exception>
		public UniversalTagBase(Asn1Reader asn) {
			if (asn == null) { throw new ArgumentNullException("asn"); }
			Init(asn);
		}
		/// <summary>
		/// Initializes a new instance of <strong>UniversalTagBase</strong> from a ASN.1-encoded byte array.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		/// <exception cref="ArgumentNullException"><strong>asn</strong> parameter is null reference.</exception>
		protected UniversalTagBase(Byte[] rawData) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			Init(new Asn1Reader(rawData));
		}

		/// <summary>
		/// Gets the numeric tag value of the current ASN type.
		/// </summary>
		public Byte Tag { get; private set; }
		/// <summary>
		/// Gets the textual name of the ASN tag.
		/// </summary>
		public String TagName { get; private set; }
		/// <summary>
		/// Indicates whether the current structure is container.
		/// </summary>
		/// <remarks>
		///		The following primitive types cannot have encapsulated structures:
		/// <list type="bullet">
		///		<item>BOOLEAN</item>
		///		<item>INTEGER</item>
		///		<item>NULL</item>
		///		<item>OBJECT_IDENTIFIER</item>
		///		<item>ENUMERATED</item>
		///		<item>RELATIVE-OID</item>
		/// </list>
		/// </remarks>
		public Boolean IsContainer { get; private set; }
		/// <summary>
		/// Gets the full tag raw data, including header and payload information.
		/// </summary>
		public Byte[] RawData { get; private set; }

		/// <summary>
		/// Initializes <strong>UniversalTagBase</strong> object from an existing <see cref="Asn1Reader"/> object.
		/// </summary>
		/// <param name="asn">Existing <see cref="Asn1Reader"/> object.</param>
		protected void Init(Asn1Reader asn) {
			Tag = asn.Tag;
			TagName = asn.TagName;
			IsContainer = asn.IsConstructed;
			RawData = asn.GetTagRawData();
		}
		/// <summary>
		/// Constant string to display error message for tag mismatch exceptions.
		/// </summary>
		protected const String InvalidType = "Input data does not represent valid {0} object.";

		/// <summary>
		/// Gets decoded tag value. If the value cannot be decoded, a hex dump is returned.
		/// </summary>
		/// <returns>Decoded tag value.</returns>
		public virtual String GetDisplayValue() {
			return RawData == null
				? String.Empty
				: AsnFormatter.BinaryToString(RawData, EncodingType.HexRaw, EncodingFormat.NOCRLF);
		}
		/// <summary>
		/// Encodes current tag to either, Base64 or hex string. For more details and available encoding options
		/// see <see cref="Crypt32Managed.CryptBinaryToString">CryptBinaryToString</see> managed method.
		/// </summary>
		/// <param name="encoding">Specifies the output encoding.</param>
		/// <returns>Encoded text value.</returns>
		public virtual String Format(EncodingType encoding = EncodingType.Base64) {
			return RawData == null
				? String.Empty
				: AsnFormatter.BinaryToString(RawData, encoding, 0);
		}
	}
}
