using System;
using System.Collections.Generic;

using TheBlueSky.SwiftAuthenticator.Externals;

namespace TheBlueSky.SwiftAuthenticator.Test
{
	public static partial class AuthenticatorTest
	{
		public static partial class GenerateCounterBasedPasswordTest
		{
			// test data from https://tools.ietf.org/html/rfc4226#appendix-D
			[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
			public static IEnumerable<object[]> GetExpectedCounterBasedPasswords(int digits)
			{
				yield return new object[] { digits, 0, "1284755224" };
				yield return new object[] { digits, 1, "1094287082" };
				yield return new object[] { digits, 2, "0137359152" };
				yield return new object[] { digits, 3, "1726969429" };
				yield return new object[] { digits, 4, "1640338314" };
				yield return new object[] { digits, 5, "0868254676" };
				yield return new object[] { digits, 6, "1918287922" };
				yield return new object[] { digits, 7, "0082162583" };
				yield return new object[] { digits, 8, "0673399871" };
				yield return new object[] { digits, 9, "0645520489" };
			}
		}

		public static partial class GenerateTimeBasedPasswordTest
		{
			// test data from https://tools.ietf.org/html/rfc6238#appendix-B and its errata https://www.rfc-editor.org/errata_search.php?rfc=6238
			[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
			public static IEnumerable<object[]> GetExpectedTimeBasedPasswordsSHA1(int digits)
			{
				var secret = Base32.ToBase32("3132333435363738393031323334353637383930".ToByteArray());
				var startDateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // Unix epoch

				yield return new object[] { secret, digits, startDateTime.AddSeconds(59), AuthenticatorAlgorithm.HMACSHA1, "94287082" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1111111109), AuthenticatorAlgorithm.HMACSHA1, "07081804" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1111111111), AuthenticatorAlgorithm.HMACSHA1, "14050471" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1234567890), AuthenticatorAlgorithm.HMACSHA1, "89005924" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(2000000000), AuthenticatorAlgorithm.HMACSHA1, "69279037" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(20000000000), AuthenticatorAlgorithm.HMACSHA1, "65353130" };
			}

			// test data from https://tools.ietf.org/html/rfc6238#appendix-B and its errata https://www.rfc-editor.org/errata_search.php?rfc=6238
			[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
			public static IEnumerable<object[]> GetExpectedTimeBasedPasswordsSHA256(int digits)
			{
				var secret = Base32.ToBase32("3132333435363738393031323334353637383930313233343536373839303132".ToByteArray());
				var startDateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // Unix epoch

				yield return new object[] { secret, digits, startDateTime.AddSeconds(59), AuthenticatorAlgorithm.HMACSHA256, "46119246" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1111111109), AuthenticatorAlgorithm.HMACSHA256, "68084774" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1111111111), AuthenticatorAlgorithm.HMACSHA256, "67062674" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1234567890), AuthenticatorAlgorithm.HMACSHA256, "91819424" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(2000000000), AuthenticatorAlgorithm.HMACSHA256, "90698825" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(20000000000), AuthenticatorAlgorithm.HMACSHA256, "77737706" };
			}

			// test data from https://tools.ietf.org/html/rfc6238#appendix-B and its errata https://www.rfc-editor.org/errata_search.php?rfc=6238
			[System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
			public static IEnumerable<object[]> GetExpectedTimeBasedPasswordsSHA512(int digits)
			{
				var secret = Base32.ToBase32("31323334353637383930313233343536373839303132333435363738393031323334353637383930313233343536373839303132333435363738393031323334".ToByteArray());
				var startDateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // Unix epoch

				yield return new object[] { secret, digits, startDateTime.AddSeconds(59), AuthenticatorAlgorithm.HMACSHA512, "90693936" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1111111109), AuthenticatorAlgorithm.HMACSHA512, "25091201" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1111111111), AuthenticatorAlgorithm.HMACSHA512, "99943326" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(1234567890), AuthenticatorAlgorithm.HMACSHA512, "93441116" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(2000000000), AuthenticatorAlgorithm.HMACSHA512, "38618901" };
				yield return new object[] { secret, digits, startDateTime.AddSeconds(20000000000), AuthenticatorAlgorithm.HMACSHA512, "47863826" };
			}
		}

		private static byte[] ToByteArray(this string hexString)
		{
			var numberChars = hexString.Length;
			var bytes = new byte[numberChars / 2];

			for (var i = 0; i < numberChars; i += 2)
			{
				bytes[i / 2] = Convert.ToByte(hexString.Substring(i, 2), 16);
			}

			return bytes;
		}
	}
}
