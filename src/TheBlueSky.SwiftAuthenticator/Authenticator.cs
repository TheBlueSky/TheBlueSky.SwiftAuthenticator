using System;
using System.Security.Cryptography;
using System.Text;

using TheBlueSky.SwiftAuthenticator.Externals;

namespace TheBlueSky.SwiftAuthenticator
{
	public sealed class Authenticator
	{
		private readonly AuthenticatorOptions options = new AuthenticatorOptions();

		public Authenticator(Action<AuthenticatorOptions> setupAction = null)
		{
			setupAction?.Invoke(this.options);
		}

		public AuthenticatorAlgorithm AuthenticatorAlgorithm => this.options.AuthenticatorAlgorithm;

		public int NumberOfPasswordDigits => this.options.NumberOfPasswordDigits;

		public int SizeOfTimeStep => this.options.SizeOfTimeStep;

		public DateTime StartDateTime => this.options.StartDateTime;

		public string GenerateCounterBasedPassword(string secret, ulong iterationNumber)
		{
			return this.GenerateCounterBasedPassword(secret, iterationNumber, this.NumberOfPasswordDigits);
		}

		public string GenerateCounterBasedPassword(string secret, ulong iterationNumber, int digits)
		{
			if (this.AuthenticatorAlgorithm != AuthenticatorAlgorithm.HMACSHA1)
			{
				throw new InvalidOperationException("HMAC-SHA-1 is the only supported algorithm when generating counter-based passwords (refert to https://tools.ietf.org/html/rfc4226#section-5).");
			}

			return this.GeneratePassword(secret, iterationNumber, digits);
		}

		public string GenerateSecret(int size = 20)
		{
			if (size % 5 != 0 || size < 5)
			{
				throw new ArgumentException(
					"The size must be multiples of 40 bits, due to Base32 encoding requirements (refert to https://tools.ietf.org/html/rfc4648#section-6).",
					nameof(size));
			}

			var buffer = new byte[size];

			using (var rng = new RNGCryptoServiceProvider())
			{
				rng.GetBytes(buffer);
			}

			return Base32.ToBase32(buffer);
		}

		public string GenerateTimeBasedPassword(string secret, Func<DateTime> nowFunc = null)
		{
			return this.GenerateTimeBasedPassword(secret, nowFunc, this.NumberOfPasswordDigits, this.SizeOfTimeStep);
		}

		public string GenerateTimeBasedPassword(string secret, Func<DateTime> nowFunc, int digits = 6, int timeStep = 30)
		{
			if (timeStep < 1)
			{
				throw new ArgumentException(
					"The time step value must be a positive Int32 value.",
					nameof(timeStep));
			}

			var now = nowFunc == null ? DateTime.UtcNow : nowFunc();

			if (now < this.StartDateTime)
			{
				throw new ArgumentException(
					$"The value produced by {nameof(nowFunc)} must be greater than the value of {nameof(Authenticator)}.{this.StartDateTime}.",
					nameof(nowFunc));
			}

			var counter = (ulong)((now - this.StartDateTime).TotalSeconds / timeStep);

			return this.GeneratePassword(secret, counter, digits);
		}

		private string GeneratePassword(string secret, ulong iterationNumber, int digits)
		{
			if (secret == null)
			{
				throw new ArgumentNullException(nameof(secret));
			}

			if (digits < 6)
			{
				throw new ArgumentException(
					"The password value must be at least a 6-digit value (refer to https://tools.ietf.org/html/rfc4226#section-4).",
					nameof(digits));
			}

			if (digits > 10)
			{
				throw new ArgumentException(
					"The password value is at most a 10-digit value, due to the maximum value of Int32.",
					nameof(digits));
			}

			var counter = BitConverter.GetBytes(iterationNumber);

			if (BitConverter.IsLittleEndian)
			{
				Array.Reverse(counter);
			}

			var key = Encoding.ASCII.GetBytes(secret);

			if (key.Length < 16)
			{
				throw new ArgumentException(
					"The length of the shared secret must be at least 128 bits (refer to https://tools.ietf.org/html/rfc4226#section-4).",
					nameof(secret));
			}

			using (var hmac = this.GetHMACAlgorithm(key))
			{
				var hash = hmac.ComputeHash(counter);
				var offset = hash[hash.Length - 1] & 0xf;

				var binary =
					((hash[offset + 0] & 0x7f) << 24) |
					((hash[offset + 1] & 0xff) << 16) |
					((hash[offset + 2] & 0xff) << 08) |
					((hash[offset + 3] & 0xff) << 00);

				var password = binary % (int)Math.Pow(10, digits);

				return password.ToString(new string('0', digits));
			}
		}

		private HMAC GetHMACAlgorithm(byte[] key)
		{
			switch (this.AuthenticatorAlgorithm)
			{
				case AuthenticatorAlgorithm.HMACSHA1:
					return new HMACSHA1(key, true);

				case AuthenticatorAlgorithm.HMACSHA256:
					return new HMACSHA256(key);

				case AuthenticatorAlgorithm.HMACSHA512:
					return new HMACSHA512(key);

				default:
					throw new InvalidOperationException("The supported algorithms are HMAC-SHA-1 for HOTP and TOTP, as well as HMAC-SHA-256 and HMAC-SHA-512 for TOTP.");
			}
		}
	}
}
