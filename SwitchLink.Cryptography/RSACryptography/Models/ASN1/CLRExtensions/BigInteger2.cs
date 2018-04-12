using Org.BouncyCastle.Math;
using System;
using System.Linq;


namespace SwitchLink.Cryptography.RSACryptography.Models.Asn1.CLRExtensions {
    /// <summary>
    /// Extension class for <see cref="BigInteger"/> class.
    /// </summary>
	static class BigInteger2 {
        /// <summary>
        /// Gets a byte array in the big-endian order.
        /// </summary>
        /// <param name="bigInteger">An <see cref="BigInteger"/> class instance.</param>
        /// <returns>Byte array in a big-endian order.</returns>
		public static Byte[] GetAsnBytes(this BigInteger bigInteger) {
			return bigInteger.ToByteArray().Reverse().ToArray();
		}
	}
}
