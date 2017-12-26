using System;

namespace TheBlueSky.SwiftAuthenticator
{
	public sealed class AuthenticatorOptions
	{
		public static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

		public AuthenticatorAlgorithm AuthenticatorAlgorithm { get; set; } = AuthenticatorAlgorithm.HMACSHA1;

		public int NumberOfPasswordDigits { get; set; } = 6;

		public int SizeOfTimeStep { get; set; } = 30;

		public DateTime StartDateTime { get; set; } = UnixEpoch;
	}
}
