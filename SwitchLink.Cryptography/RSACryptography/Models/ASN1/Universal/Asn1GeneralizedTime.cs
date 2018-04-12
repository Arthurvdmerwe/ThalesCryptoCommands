using SwitchLink.Cryptography.RSACryptography.Models.Asn1.Utils;
using System;
using System.Globalization;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal {
	/// <summary>
	/// Represents ASN.1 <strong>GeneralizedTime</strong> universal tag.
	/// </summary>
	public sealed class Asn1GeneralizedTime : UniversalTagBase {
		DateTime tagValue;
		TimeZoneInfo zoneInfo;
		const Byte tag = (Byte)Asn1Type.Generalizedtime;
		const String tagName = "Generalized Time";

		/// <summary>
		/// Initializes a new instance of the <strong>Asn1GeneralizedTime</strong> class from a date time object
		/// to encode and value that indiciates whether to include millisecond information.
		/// </summary>
		/// <param name="time">A <see cref="DateTime"/> object.</param>
		/// <param name="precisetime">
		/// <strong>True</strong> if encoded value should contain millisecond information, otherwise <strong>False</strong>.
		/// </param>
		public Asn1GeneralizedTime(DateTime time, Boolean precisetime) : this(time, null, precisetime) { }
		/// <summary>
		/// Initializes a new instance of the <strong>Asn1GeneralizedTime</strong> class from a date time object
		/// to encode, time zone information and value that indiciates whether to include millisecond information.
		/// </summary>
		/// <param name="time">A <see cref="DateTime"/> object.</param>
		/// <param name="zone">A <see cref="TimeZoneInfo"/> object that represents time zone information.</param>
		/// <param name="preciseTime">
		/// <strong>True</strong> if encoded value should contain millisecond information, otherwise <strong>False</strong>.
		/// </param>
		public Asn1GeneralizedTime(DateTime time, TimeZoneInfo zone = null, Boolean preciseTime = false) {
			m_encode(time, zone, preciseTime);
		}
		/// <summary>
		/// Initializes a new instance of the <strong>Asn1GeneralizedTime</strong> class from an existing
		/// <see cref="Asn1Reader"/> object.
		/// </summary>
		/// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents Generalized Time.</param>
		/// <exception cref="Asn1InvalidTagException">
		/// The current state of <strong>ASN1</strong> object is not Generalized Time.
		/// </exception>
		public Asn1GeneralizedTime(Asn1Reader asn) : base(asn) {
			if (asn.Tag != tag) {
				throw new Asn1InvalidTagException(String.Format(InvalidType, tagName));
			}
			m_decode(asn.GetTagRawData());
		}
		/// <summary>
		/// Initializes a new instance of the <strong>Asn1GeneralizedTime</strong> class from a byte array that
		/// represents encoded UTC time.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		/// <exception cref="Asn1InvalidTagException">
		/// The current state of <strong>ASN1</strong> object is not Generalized Time.
		/// </exception>
		public Asn1GeneralizedTime(Byte[] rawData) : base(rawData) {
			if (rawData[0] != tag) {
				throw new Asn1InvalidTagException(String.Format(InvalidType, tagName));
			}
			m_decode(rawData);
		}

		/// <summary>
		/// Gets the date/time value of the current object.
		/// </summary>
		public DateTime Value {
			get { return tagValue; }
		}
		/// <summary>
		/// Gets the time zone information for the current object.
		/// </summary>
		public TimeZoneInfo ZoneInfo {
			get { return zoneInfo; }
		}

		void m_encode(DateTime time, TimeZoneInfo zone, Boolean preciseTime) {
			tagValue = time;
			zoneInfo = zone;
			Init(new Asn1Reader(Asn1Utils.Encode(DateTimeUtils.Encode(time, zone, false, preciseTime), tag)));
		}
		void m_decode(Byte[] rawData) {
			Asn1Reader asn = new Asn1Reader(rawData);
			Init(asn);
			tagValue = DateTimeUtils.Decode(asn, out zoneInfo);
		}

		/// <summary>
		/// Deocdes a date/time object from an <see cref="Asn1Reader"/> object in the position that represents
		/// Generalized Time.
		/// </summary>
		/// <param name="asn"><see cref="Asn1Reader"/> object in the position that represents Generalized Time.</param>
		/// <exception cref="ArgumentNullException">
		/// <strong>asn</strong> parameter is null reference.
		/// </exception>
		/// <exception cref="Asn1InvalidTagException">
		/// The current state of <strong>ASN1</strong> object is not Generalized Time.
		/// </exception>
		/// <returns>Decoded date/time object.</returns>
		public static DateTime Decode(Asn1Reader asn) {
			if (asn == null) { throw new ArgumentNullException("asn"); }
			if (asn.Tag != tag) {
				throw new Asn1InvalidTagException(String.Format(InvalidType, tagName));
			}
			TimeZoneInfo zone;
			return DateTimeUtils.Decode(asn, out zone);
		}

		/// <summary>
		/// Gets decoded date/time string value.
		/// </summary>
		/// <returns>Decoded date/time string value.</returns>
		public override string GetDisplayValue() {
			return Value.ToString(CultureInfo.InvariantCulture);
		}
	}
}
