using System;
using System.Collections.Generic;
using System.Linq;
using SwitchLink.Cryptography.RSACryptography.Models.Asn1.CLRExtensions.Generics;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Tree {
	public class Asn1Tree : IAsn1TreeSource {

		public Asn1Tree(Byte[] rawBytes) : this(new Asn1Reader(rawBytes)) { }
		public Asn1Tree(Asn1Reader asn) {
			if (asn == null) { throw new ArgumentNullException("asn"); }
			RawData = new ObservableList<Byte>(true);
			RawData.AddRange(asn.RawData);
			m_initialize(asn);
		}

		public Asn1Node RootNode { get; private set; }
		public ObservableList<Byte> RawData { get; set; }

		void m_initialize(Asn1Reader asn) {
			asn.BuildOffsetMap();
			RootNode = new Asn1Node(asn, this);
			if (asn.NextOffset == 0) {
				return;
			}
			buildTree(asn, RootNode, this);
		}
		static void buildTree(Asn1Reader asn, Asn1Node node, Asn1Tree rootTree) {
			asn.MoveNext();
			List<Int32> subNodeIndexes = new List<Int32>();
			Int32 index = 0;
			do {
				node.AddUnsafe(new Asn1Node(asn, rootTree));
				if (asn.IsConstructed) {
					subNodeIndexes.Add(index);
				}
				index++;
			} while (asn.MoveNextCurrentLevel());
			asn.Reset();
			foreach (Int32 subNodeIndex in subNodeIndexes) {
				Asn1Node subNode = node.Children[subNodeIndex];
				asn.MoveToPoisition(subNode.Offset);
				buildTree(asn, subNode, rootTree);
			}
		}

		

	}
}
