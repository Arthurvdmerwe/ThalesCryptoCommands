using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Tree {
	public class Asn1Node : GenericAsn1Tree<Asn1Node>, IAsn1NodeValue {
		Boolean invalidData;
		Byte tag, unusedBits;
		Int32 offset, payloadLength;
		String tagName;
        Byte[] rawData;

		public Asn1Node(Asn1Reader asn, IAsn1TreeSource source) : base(source) {
			initialize(asn);
		}

		public Byte Tag {
			get { return tag; }
			private set {
				tag = value;
				OnPropertyChanged("Tag");
			}
		}
		public String TagName {
			get { return tagName; }
			private set {
				tagName = value;
				OnPropertyChanged("TagName");
			}
		}
		public Int32 Offset {
			get { return offset; }
			set {
				offset = value;
				OnPropertyChanged("Offset");
                // TODO: is this necessary?
				OnPropertyChanged("PayloadStartOffset");
			}
		}
		public Int32 PayloadStartOffset {
			get {
				return Tag == (Byte)Asn1Type.BIT_STRING
					? Offset + 1 + HeaderLength
					: Offset + HeaderLength;
			}
		}
		public Int32 HeaderLength {
			get { return Asn1Utils.GetLengthBytes(PayloadLength).Length + 1; }
		}
		public Int32 PayloadLength {
			get { return payloadLength; }
			set {
				payloadLength = value;
				OnPropertyChanged("PayloadLength");
			}
		}
		public Int32 TagLength {
			get { return HeaderLength + PayloadLength; }
		}
		public String TextValue { get; private set; }
		public Boolean HasInvalidData {
			get { return invalidData; }
			set {
				invalidData = value;
				OnPropertyChanged("HasInvalidData");
			}
		}

		void initialize(Asn1Reader asn) {
			Tag = asn.Tag;
			TagName = asn.TagName;
			Offset = asn.Offset;
			PayloadLength = asn.PayloadLength;
			getTextValue(asn);
			getUnusedBits(asn);
            if (!asn.IsConstructed) {
                rawData = asn.GetPayload();
            }
		}
		void getTextValue(Asn1Reader asn) {
			if (asn.IsConstructed) { return; }
			try {
				TextValue = Asn1Utils.GetViewValue(asn);
			} catch {
				invalidData = true;
			}
		}
		void getUnusedBits(Asn1Reader asn) {
			if (Tag != (Byte)Asn1Type.BIT_STRING || asn.PayloadLength <= 0) { return; }
			unusedBits = asn.RawData[asn.PayloadStartOffset];
		}

		public void SetValue(String newValue, Byte unusedBits = 0) {
			Byte[] binValue;
			//binValue = Asn1Utils.EncodeGeneric(Tag, newValue, unused);
			NotifyChangeLength(0);
		}
        public Byte[] GetRawData() {
            if (rawData == null) {
                List<Byte> childRawData = new List<Byte>();
                foreach (Asn1Node child in Children) {
                    childRawData.AddRange(child.GetRawData());
                }
                return Asn1Utils.Encode(childRawData.ToArray(), Tag);
            }
            return Asn1Utils.Encode(rawData, Tag);
        }
	}
}
