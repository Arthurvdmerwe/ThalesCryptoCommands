using System;

namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Tree {
    /// <summary>
    /// Defines the minimum member set of the object that is used as a node in the <see cref="GenericAsn1Tree{T}"/>
    /// </summary>
    /// <remarks>
    /// TODO
    /// </remarks>
	public interface IAsn1NodeValue {
        /// <summary>
        /// Gets the tag of the current node instance.
        /// </summary>
		Byte Tag { get; }
        /// <summary>
        /// Gets or sets the start offset of the current node instance.
        /// </summary>
		Int32 Offset { get; set; }
        /// <summary>
        /// Gets or sets the payload length of the current node instance.
        /// </summary>
		Int32 PayloadLength { get; set; }
        /// <summary>
        /// Gets the ASN header length. This includes tag byte and length byte.
        /// Minimum value is 2 bytes and maximum value can be 5 bytes.
        /// </summary>
		Int32 HeaderLength { get; }
        /// <summary>
        /// Gets the full tag length. This includes ASN header and payload. For BIT_STRING, this includes an
        /// <strong>unusedBits</strong> byte.
        /// </summary>
		Int32 TagLength { get; }
        /// <summary>
        /// Gets the current node's value as a byte array.
        /// </summary>
        /// <returns>ASN.1-encoded byte array.</returns>
        Byte[] GetRawData();
	}
}