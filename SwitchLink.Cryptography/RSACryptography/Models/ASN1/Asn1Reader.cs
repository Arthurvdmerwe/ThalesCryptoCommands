﻿using SwitchLink.Cryptography.RSACryptography.Models.Asn1.Universal;
using SwitchLink.Cryptography.RSACryptography.Models.Asn1.Utils;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1
{
    /// <summary>
    /// Provides a set of properties and generic methods to work with ASN.1 structures in Distinguished Encoding
    /// Rules (<strong>DER</strong>) encoding.
    /// </summary>
    /// <remarks>Static methods of this class provides an encoders and decoders for the generic .NET types and unmanaged structures.
    /// <p>Static methods (except <see cref="Asn1Utils.Encode(Byte[], Byte)">Encode</see>) strictly verifies whether the encoded or source data
    /// is valid for the specific ASN.1 type. If the data is not appropriate for the method, it returns <see cref="InvalidDataException"/></p></remarks>
    public class Asn1Reader {
		// a list of primitive tags. Source: http://en.wikipedia.org/wiki/Distinguished_Encoding_Rules#DER_encoding
		static readonly List<Byte> _excludedTags = new List<Byte>(
			new Byte[] { 0, 1, 2, 5, 6, 9, 10, 13 }
		);
		readonly Dictionary<Int64, AsnInternalMap> _offsetMap = new Dictionary<Int64, AsnInternalMap>();
        readonly List<Byte> _multiNestedTypes = new List<Byte>(
            new[] {
                (Byte)Asn1Type.SEQUENCE,
                (Byte)((Byte)Asn1Type.SEQUENCE | (Byte)Asn1Class.CONSTRUCTED),
                (Byte)Asn1Type.SET,
                (Byte)((Byte)Asn1Type.SET | (Byte)Asn1Class.CONSTRUCTED)
            }
        );
		AsnInternalMap currentPosition;
		Int32 childCount;
        Boolean? isTaggedConstructed;

        /// <summary>
        /// Initializes a new instance of the <strong>ASN1</strong> class from an existing
        /// <strong>ASN1</strong> object.
        /// </summary>
        /// <param name="asn">An existing <strong>ASN1</strong> object.</param>
        /// <remarks>
        ///		This constructor creates a copy of a current position of an exisiting <strong>ASN1</strong> object.
        /// </remarks>
        public Asn1Reader(Asn1Reader asn) : this(asn.GetTagRawData()) { }
		/// <summary>
		/// Initializes a new instance of the <strong>ASN1</strong> class by using an ASN.1 encoded byte array.
		/// </summary>
		/// <param name="rawData">ASN.1-encoded byte array.</param>
		/// <exception cref="ArgumentNullException">
		///     <strong>rawData</strong> parameter is null reference.
		/// </exception>
		/// <exception cref="InvalidDataException">
		///     The data in the <strong>rawData</strong> parameter is not valid ASN sequence.
		/// </exception>
		/// <remarks>
		///     If <strong>rawData</strong> size is greater than outer structure size, constructor will take only required
		///     bytes from input data.
		/// </remarks>
		public Asn1Reader(Byte[] rawData) : this(rawData, 0) { }

		Asn1Reader(Byte[] rawData, Int32 offset) {
			if (rawData == null) { throw new ArgumentNullException("rawData"); }
			if (rawData.Length < 2) { throw new Win32Exception(Strings.InvalidDataException); }
			currentPosition = new AsnInternalMap();
			_offsetMap.Add(0, currentPosition);
			m_initialize(rawData, offset);
		}

		/// <summary>
		/// Gets current position in the byte array stored in <see cref="RawData"/> property.
		/// </summary>
		public Int32 Offset { get; private set; }
		/// <summary>
		/// Gets current structure's tag.
		/// </summary>
		public Byte Tag { get; private set; }
		/// <summary>
		/// Gets current structure tag name.
		/// </summary>
		public String TagName { get; private set; }
		/// <summary>
		/// Gets current structure full length. Full length contains tag, tag length byte (or bytes) and tag payload.
		/// </summary>
		public Int32 TagLength { get; private set; }
		/// <summary>
		/// Gets a position at which current structure's payload starts (excluding tag and tag length byte (or bytes)).
		/// </summary>
		public Int32 PayloadStartOffset { get; private set; }
		/// <summary>
		/// Gets the length of the current structure's payload.
		/// </summary>
		public Int32 PayloadLength { get; private set; }
		/// <summary>
		/// This property is sibject to change.
		/// </summary>
		public Int32 NextCurrentLevelOffset { get; private set; }
		/// <summary>
		/// Gets next structure's offset. If current element is the last element in the data, the property returns zero.
		/// </summary>
		public Int32 NextOffset { get; private set; }
		/// <summary>
		/// Indicates whether the current tag is container, so it have childs instead of explicit tag balue.
		/// </summary>
		public Boolean IsConstructed { get; private set; }
		/// <summary>
		/// Get's original ASN.1-encoded byte array.
		/// </summary>
		public Byte[] RawData { get; private set; }

		void m_initialize(Byte[] raw, Int32 pOffset) {
			//if (currentPosition == null) {
			//	_offsetMap.Add(0, new AsnInternalMap());
			//}
			IsConstructed = false;
            if (raw != null) { RawData = raw; }
			Offset = pOffset;
			Tag = RawData[Offset];
			calculateLength();
			// strip possible unnecessary bytes
			if (raw != null && TagLength != RawData.Length) {
				RawData = raw.Take(TagLength).ToArray();
			}
			getTagName(Tag);
			// 0 Tag is reserved for BER and is not available in DER
			if (Tag == 0) {
				throw new Asn1InvalidTagException(Offset);
			}
			if (PayloadLength == 0) {
				NextOffset = Offset + TagLength == RawData.Length
					? 0
					: Offset + TagLength;
				// TODO check this
				NextCurrentLevelOffset = currentPosition.LevelEnd == 0 || Offset - currentPosition.LevelStart + TagLength == currentPosition.LevelEnd
					? 0
					: NextOffset;
				//NextCurrentLevelOffset = NextOffset;
				return;
			}
			parseNestedType();
			NextCurrentLevelOffset = Offset - currentPosition.LevelStart + TagLength < currentPosition.LevelEnd
				? Offset + TagLength
				: 0;
			NextOffset = IsConstructed
				? (Tag == 3
					// skip unused bits byte
					? PayloadStartOffset + 1
					: PayloadStartOffset)
				: (Offset + TagLength < RawData.Length
					? Offset + TagLength
					: 0);
		}
	    void parseNestedType() {
            // processing rules (assuming zero-based bits):
            // if bit 5 is set to "1", or the type is SEQUENCE/SET -- the type is constructed. Unroll nested types.
            // if bit 5 is set to "0", attempt to resolve nested types only for UNIVERSAL tags.
            if (_excludedTags.Contains(Tag) || PayloadLength <= 2) { return; }
            Int64 pstart = PayloadStartOffset;
            Int32 plength = PayloadLength;
	        if (Tag == 3) {
	            pstart = PayloadStartOffset + 1;
	            plength = PayloadLength - 1;
	        }
            if (_multiNestedTypes.Contains(Tag) || (Tag & (Byte)Asn1Class.CONSTRUCTED) > 0) {
                IsConstructed = true;
                if (!_offsetMap.ContainsKey(pstart)) {
                    predict(pstart, plength, true, out childCount);
                }
                isTaggedConstructed = null;
                return;
            }
            if (Tag > 0 && Tag < (Byte)Asn1Type.TAG_MASK) {
                IsConstructed = predict(pstart, plength, false, out childCount);
                // reiterate again and build map for children
                if (IsConstructed && !_offsetMap.ContainsKey(pstart)) {
                    predict(pstart, plength, true, out childCount);
                }
            }
	        isTaggedConstructed = null;
	    }
        Boolean predict(Int64 start, Int32 projectedLength, Boolean assignMap, out Int32 estimatedChildCount) {
            Int64 levelStart = start;
            Int64 sum = 0;
            estimatedChildCount = 0;
            do {
                if (start < 0 || start >= RawData.Length || RawData[start] == 0) { return false; }
                Int64 pl = calculatePredictLength(start);
                sum += pl;
                if (assignMap && sum <= projectedLength) {
                    _offsetMap.Add(start, new AsnInternalMap { LevelStart = levelStart, LevelEnd = projectedLength });
                }
                start += pl;
                //estimatedChildCount++;
            } while (sum < projectedLength);
            if (sum != projectedLength) { estimatedChildCount = 0; }
            return sum == projectedLength;
        }
        void calculateLength() {
			if (RawData[Offset + 1] < 128) {
				PayloadStartOffset = Offset + 2;
				PayloadLength = RawData[Offset + 1];
				TagLength = PayloadLength + 2;
			} else {
				Int32 lengthbytes = RawData[Offset + 1] - 128;
				// max length can be encoded by using 4 bytes.
				if (lengthbytes > 4) {
					throw new OverflowException("Data length is too large.");
				}
				PayloadStartOffset = Offset + 2 + lengthbytes;
				PayloadLength = RawData[Offset + 2];
				for (Int32 i = Offset + 3; i < PayloadStartOffset; i++) {
					PayloadLength = (PayloadLength << 8) | RawData[i];
				}
				TagLength = PayloadLength + lengthbytes + 2;
			}
		}
		Int64 calculatePredictLength(Int64 offset) {
			if (offset + 1 >= RawData.Length || offset < 0) { return Int32.MaxValue; }
			if (RawData[offset + 1] < 128) {
				return RawData[offset + 1] + 2;
			}
			Int32 lengthbytes = RawData[offset + 1] - 128;
			// max length can be encoded by using 4 bytes.
			if (lengthbytes > 4) {
				return Int32.MaxValue;
			}
			Int32 ppayloadLength = RawData[offset + 2];
			for (Int64 i = offset + 3; i < offset + 2 + lengthbytes; i++) {
				ppayloadLength = (ppayloadLength << 8) | RawData[i];
			}
			// 2 -- transitional + tag
			return ppayloadLength + lengthbytes + 2;
		}
		void getTagName(Byte tag) {
			if ((tag & (Byte)Asn1Class.PRIVATE) != 0) {
				switch (tag & (Byte)Asn1Class.PRIVATE) {
					case (Byte)Asn1Class.CONTEXT_SPECIFIC:
						TagName = "CONTEXT SPECIFIC (" + (tag & 31) + ")";
                        isTaggedConstructed = (tag & (Byte)Asn1Class.CONSTRUCTED) > 0;
						break;
					case (Byte)Asn1Class.APPLICATION:
						TagName = "APPLICATION (" + (tag & 31) + ")";
						break;
					case (Byte)Asn1Class.PRIVATE:
						TagName = "PRIVATE (" + (tag & 31) + ")";
						break;
					case (Byte)Asn1Class.CONSTRUCTED:
						TagName = "CONSTRUCTED (" + (tag & 31) + ")";
						break;
				}
			} else {
				TagName = ((Asn1Type)(tag & 31)).ToString();
			}
		}

		/// <summary>
		/// Gets current structure header. Header contains tag and tag length byte (or bytes).
		/// </summary>
		/// <returns>Current structure header. Header contains tag and tag length byte (or bytes).</returns>
		public Byte[] GetHeader() {
			return RawData.Skip(Offset).Take(PayloadStartOffset - Offset).ToArray();
		}
		/// <summary>
		/// Gets the byte array of the current structure's payload.
		/// </summary>
		/// <returns>Byte array of the current structure's payload</returns>
		public Byte[] GetPayload() {
			return RawData.Skip(PayloadStartOffset).Take(PayloadLength).ToArray();
		}
		/// <summary>
		/// Gets the raw data of the tag, which includes tag, length bytes and payload.
		/// </summary>
		/// <returns>A full binary copy of the tag.</returns>
		public Byte[] GetTagRawData() {
			return RawData.Skip(Offset).Take(TagLength).ToArray();
		}
		/// <summary>
		/// Gets the count of nested nodes under node in the current position.
		/// </summary>
		/// <returns>Count of nested nodes.</returns>
		/// <remarks>For primitive types and empty containers this method returns 0.</remarks>
		public Int32 GetNestedNodeCount() {
			return IsConstructed ? childCount : 0;
		}
		/// <summary>
		/// Moves from the current structure to the next structure. If current structure is container or constructed type (<strong>SEQUENCE</strong>,
		/// <strong>SEQUENCE OF</strong>, <strong>SET</strong>, <strong>SET OF</strong>, <strong>OCTET STRING</strong> or <strong>context-specific</strong>),
		/// <strong>MoveNext()</strong> method moves to the inner (wrapped) structure which starts at the container's payload position.
		/// <p>If the current structure is primitive type, <strong>MoveNext()</strong> method seeks over current type to the next structure.</p>
		/// </summary>
		/// <returns><strong>True</strong> if the current structure is not the last in the data contained in <strong>RawData</strong> property and there
		/// are no inner (wrapped) structures, otherwise <strong>False</strong></returns>
		public Boolean MoveNext() {
			if (NextOffset == 0) { return false; }
			//projectedIterationSize = _offsetMap[NextOffset];
			currentPosition = _offsetMap[NextOffset];
			m_initialize(null, NextOffset);
			return true;
		}
		/// <summary>
		/// Moves over current structure to the next structure at the same level. If the current structure is a container
		/// (or constructed type), the method skips entire container.
		/// </summary>
		/// <returns><strong>True</strong> if the current structure is not the last structure at the same level (or upper
		/// level), otherwise <strong>False</strong>.</returns>
		public Boolean MoveNextCurrentLevel() {
			if (NextCurrentLevelOffset == 0) { return false; }
			currentPosition = _offsetMap[NextCurrentLevelOffset];
			m_initialize(null, NextCurrentLevelOffset);
			return true;
		}
		/// <summary>
		/// Moves to a specified start offset.
		/// </summary>
		/// <param name="newPosition">ASN structure start position (offset).</param>
		/// <returns>
		/// <strong>True</strong> if specified offset is valid and pointer was successfully set to specified position,
		/// otherwise <strong>False</strong>.
		/// </returns>
		/// <remarks>
		/// Specified poisition validity is determined based on internal map and <see cref="BuildOffsetMap"/>
		/// method must be called prior to first call of this method. Subsequent <strong>BuildOffsetMap</strong>
		/// method calls are not necessary.
		/// </remarks>
		public Boolean MoveToPoisition(Int32 newPosition) {
			if (_offsetMap == null) {
				throw new InvalidOperationException();
			}
			if (!_offsetMap.ContainsKey(newPosition)) {
				return false;
			}
			currentPosition = _offsetMap[newPosition];
			m_initialize(null, newPosition);
			return true;
		}
		/// <summary>
		/// Moves to the beginning of the file.
		/// </summary>
		public void Reset() {
			currentPosition = _offsetMap[0];
			m_initialize(null, 0);
		}
		/// <summary>
		/// Gets the appropriate primitive tag object from <strong>Universal</strong> namespace, or <see cref="UniversalTagBase"/> object.
		/// </summary>
		/// <returns>ASN.1 object that represents current tag.</returns>
		public UniversalTagBase GetTagObject() {
			switch (Tag) {
				case (Byte)Asn1Type.BIT_STRING:
					return new Asn1BitString(this);
				default:
					return new UniversalTagBase(this);
			}
		}
		/// <summary>
		/// Recursively processes ASN tree and builds internal offset map.
		/// </summary>
		/// <returns>A number of processed ASN structures.</returns>
		/// <remarks>
		/// This method resets current parser position to zero.
		/// </remarks>
		public Int32 BuildOffsetMap() {
			Reset();
			do { } while (MoveNext());
			Reset();
			return _offsetMap.Count;
		}
        /// <summary>
        /// Gets the list of tags that can be represented in a primitive form only.
        /// </summary>
        /// <returns>Byte array.</returns>
		public static List<Byte> GetRestrictedTags() {
            return _excludedTags.ToList();
		}
	}
}
