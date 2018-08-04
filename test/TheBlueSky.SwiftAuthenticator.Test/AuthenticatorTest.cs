using System;

using Xunit;

using TheBlueSky.SwiftAuthenticator.Externals;

namespace TheBlueSky.SwiftAuthenticator.Test
{
	public static partial class AuthenticatorTest
	{
		private static readonly string Secret = Base32.ToBase32("3132333435363738393031323334353637383930".ToByteArray());

		public static class AuthenticatorConstructorTest
		{
			[Fact]
			public static void PropertiesAreSetToTheirDefaultValueWhenUsingTheDefaultConstructor()
			{
				var defaultAuthenticatorAlgorithm = AuthenticatorAlgorithm.HMACSHA1;
				var defaultNumberOfPasswordDigits = 6;
				var defaultSizeOfTimeStep = 30;
				var defaultStartDateTime = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc); // Unix epoch

				var authenticator = new Authenticator();

				Assert.Equal(defaultAuthenticatorAlgorithm, authenticator.AuthenticatorAlgorithm);
				Assert.Equal(defaultNumberOfPasswordDigits, authenticator.NumberOfPasswordDigits);
				Assert.Equal(defaultSizeOfTimeStep, authenticator.SizeOfTimeStep);
				Assert.Equal(defaultStartDateTime, authenticator.StartDateTime);
			}

			[Fact]
			public static void PropertiesAreSetCorrectlyAsSpecifiedInAuthenticatorOptionsAction()
			{
				var authenticatorAlgorithm = AuthenticatorAlgorithm.HMACSHA256;
				var numberOfPasswordDigits = 8;
				var sizeOfTimeStep = 60;
				var startDateTime = new DateTime(2017, 12, 16, 08, 46, 39, DateTimeKind.Utc);

				var authenticator = new Authenticator(options =>
				{
					options.AuthenticatorAlgorithm = authenticatorAlgorithm;
					options.NumberOfPasswordDigits = numberOfPasswordDigits;
					options.SizeOfTimeStep = sizeOfTimeStep;
					options.StartDateTime = startDateTime;
				});

				Assert.Equal(authenticatorAlgorithm, authenticator.AuthenticatorAlgorithm);
				Assert.Equal(numberOfPasswordDigits, authenticator.NumberOfPasswordDigits);
				Assert.Equal(sizeOfTimeStep, authenticator.SizeOfTimeStep);
				Assert.Equal(startDateTime, authenticator.StartDateTime);
			}
		}

		public static partial class GenerateCounterBasedPasswordTest
		{
			[Fact]
			public static void ThrowArgumentNullExceptionIfSecretParameterIsNull()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentNullException>(() => authenticator.GenerateCounterBasedPassword(null, 0));
			}

			[Fact]
			public static void ThrowArgumentExceptionIfSecretParameterLengthIsLessThan128Bit()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateCounterBasedPassword(Secret.Substring(0, 10), 0));
			}

			[Theory]
			[InlineData(-1)]
			[InlineData(0)]
			[InlineData(3)]
			public static void ThrowArgumentExceptionIfDigitsParameterIsLessThanSix(int digits)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateCounterBasedPassword(Secret, 9, digits));
			}

			[Theory]
			[InlineData(13)]
			public static void ThrowArgumentExceptionIfDigitsParameterIsGreaterThanTen(int digits)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateCounterBasedPassword(Secret, 9, digits));
			}

			[Theory]
			[InlineData(AuthenticatorAlgorithm.HMACSHA256)]
			[InlineData(AuthenticatorAlgorithm.HMACSHA512)]
			[InlineData((AuthenticatorAlgorithm)5)]
			public static void ThrowInvalidOperationExceptionIfAuthenticatorAlgorithmIsNotHMACSHA1(AuthenticatorAlgorithm authenticatorAlgorithm)
			{
				var authenticator = new Authenticator(options => options.AuthenticatorAlgorithm = authenticatorAlgorithm);

				Assert.Throws<InvalidOperationException>(() => authenticator.GenerateCounterBasedPassword(Secret, 9));
			}

			[Theory]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 6)]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 8)]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 10)]
			public static void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInOptions(int digits, ulong iterationNumber, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator(options =>
				{
					options.NumberOfPasswordDigits = digits;
				});
				var actualPassword = authenticator.GenerateCounterBasedPassword(Secret, iterationNumber);

				Assert.Equal(expectedPassword, actualPassword);
			}

			[Theory]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 6)]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 8)]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 10)]
			public static void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInParameters(int digits, ulong iterationNumber, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator();
				var actualPassword = authenticator.GenerateCounterBasedPassword(Secret, iterationNumber, digits);

				Assert.Equal(expectedPassword, actualPassword);
			}

			[Theory]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 6)]
			public static void GenerateCorrectSixDigitPasswordByDefaultIfDigitsParameterIsNotSpecified(int digits, ulong iterationNumber, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator();
				var actualPassword = authenticator.GenerateCounterBasedPassword(Secret, iterationNumber);

				Assert.Equal(expectedPassword, actualPassword);
			}
		}

		public static class GenerateSecretTest
		{
			[Theory]
			[InlineData(-5)]
			[InlineData(0)]
			[InlineData(13)]
			public static void ThrowArgumentExceptionIfSizeParameterIsNotMultiplesOf40Bits(int expectedLength)
			{
				Assert.Throws<ArgumentException>(() => Authenticator.GenerateSecret(expectedLength));
			}

			[Theory]
			[InlineData(10)]
			[InlineData(15)]
			[InlineData(20)]
			public static void GenerateSecretWithCorrectLength(int expectedLength)
			{
				var secret = Authenticator.GenerateSecret(expectedLength);
				var actualLength = Base32.FromBase32(secret).Length;

				Assert.True(expectedLength == actualLength);
			}

			[Fact]
			public static void Generate20BytesSecretByDefaultIfSizeParameterIsNotSpecified()
			{
				const int expectedLength = 20;

				var secret = Authenticator.GenerateSecret();
				var actualLength = Base32.FromBase32(secret).Length;

				Assert.True(expectedLength == actualLength);
			}
		}

		public static partial class GenerateTimeBasedPasswordTest
		{
			[Fact]
			public static void ThrowArgumentNullExceptionIfSecretParameterIsNull()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentNullException>(() => authenticator.GenerateTimeBasedPassword(null));
			}

			[Fact]
			public static void ThrowArgumentExceptionIfSecretParameterLengthIsLessThan128Bit()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret.Substring(0, 10)));
			}

			[Theory]
			[InlineData(-1)]
			[InlineData(0)]
			[InlineData(3)]
			public static void ThrowArgumentExceptionIfDigitsParameterIsLessThanSix(int digits)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, digits));
			}

			[Fact]
			public static void ThrowArgumentExceptionIfDigitsParameterIsGreaterThanTen()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, 13));
			}

			[Theory]
			[InlineData(-1)]
			[InlineData(0)]
			public static void ThrowArgumentExceptionIfTimeStepParameterIsNotPositive(int timeStep)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, 6, timeStep));
			}

			[Fact]
			public static void ThrowArgumentExceptionIfNowFuncReturnsValueLessThenAuthenticatorStartDateTime()
			{
				var authenticator = new Authenticator(options => options.StartDateTime = DateTime.UtcNow);
				var now = new DateTime(2017, 12, 16, 08, 46, 39, DateTimeKind.Utc);

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, () => now, 9));
			}

			[Fact]
			public static void ThrowInvalidOperationExceptionIfAuthenticatorAlgorithmIsNotSupported()
			{
				var authenticator = new Authenticator(options => options.AuthenticatorAlgorithm = (AuthenticatorAlgorithm)5);

				Assert.Throws<InvalidOperationException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, 9));
			}

			// this method only tests 30 seconds time step from Unix epoc
			// TODO: test other than Unix epoc and 30 time step
			[Theory]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA1), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA256), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA512), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA1), 8)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA256), 8)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA512), 8)]
			public static void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInOptions(
				string secrect, int digits, DateTime now, AuthenticatorAlgorithm authenticatorAlgorithm, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator(options =>
				{
					options.AuthenticatorAlgorithm = authenticatorAlgorithm;
					options.NumberOfPasswordDigits = digits;
					options.SizeOfTimeStep = 30;
				});
				var actualPassword = authenticator.GenerateTimeBasedPassword(secrect, () => now);

				Assert.Equal(expectedPassword, actualPassword);
			}

			// this method only tests 30 seconds time step from Unix epoc
			// TODO: test other than Unix epoc and 30 time step
			[Theory]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA1), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA256), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA512), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA1), 8)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA256), 8)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA512), 8)]
			public static void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInParameters(
				string secrect, int digits, DateTime now, AuthenticatorAlgorithm authenticatorAlgorithm, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator(options => options.AuthenticatorAlgorithm = authenticatorAlgorithm);
				var actualPassword = authenticator.GenerateTimeBasedPassword(secrect, () => now, digits, 30);

				Assert.Equal(expectedPassword, actualPassword);
			}

			[Theory]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA1), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA256), 6)]
			[MemberData(nameof(GetExpectedTimeBasedPasswordsSHA512), 6)]
			public static void GenerateCorrectSixDigitPasswordWith30SecondsStepByDefaultIfDigitsAndTimeStepParametersAreNotSpecified(
				string secrect, int digits, DateTime now, AuthenticatorAlgorithm authenticatorAlgorithm, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator(options => options.AuthenticatorAlgorithm = authenticatorAlgorithm);
				var actualPassword = authenticator.GenerateTimeBasedPassword(secrect, () => now);

				Assert.Equal(expectedPassword, actualPassword);
			}
		}
	}
}
