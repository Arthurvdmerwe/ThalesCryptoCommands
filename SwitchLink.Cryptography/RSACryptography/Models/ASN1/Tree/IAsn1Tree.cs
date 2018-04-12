
using SwitchLink.Cryptography.RSACryptography.Models.Asn1.CLRExtensions.Generics;
using System;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Tree {
    /// <summary>
    /// Defines data source members in the ASN.1 tree class.
    /// </summary>
	public interface IAsn1TreeSource {
        /// <summary>
        /// Gets the byte array that holds ASN.1-encoded byte array.
        /// </summary>
        /// <remarks>Interface implementations shall not modify this member on its own.</remarks>
		ObservableList<Byte> RawData { get; }
	}
}