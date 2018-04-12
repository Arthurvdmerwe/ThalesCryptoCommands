namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.Tree {
	/// <summary>
	/// Contains enumerations to identify ASN.1 tree node insertion option.
	/// </summary>
	public enum InsertNodeOption {
		/// <summary>
		/// The node inserted before selected node.
		/// </summary>
		Before,
		/// <summary>
		/// The node inserted after selected node.
		/// </summary>
		After,
		/// <summary>
		/// The node is inserted as a last child of the current parent.
		/// </summary>
		Last
	}
}
