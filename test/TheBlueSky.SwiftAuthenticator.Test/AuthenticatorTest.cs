using System;

using Xunit;

using TheBlueSky.SwiftAuthenticator.Externals;

namespace TheBlueSky.SwiftAuthenticator.Test
{
	public static partial class AuthenticatorTest
	{
		private const string Secret = "12345678901234567890";

		public sealed class AuthenticatorConstructorTest
		{
			[Fact]
			public void PropertiesAreSetToTheirDefaultValueWhenUsingTheDefaultConstructor()
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
			public void PropertiesAreSetCorrectlyAsSpecifiedInAuthenticatorOptionsAction()
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

		public sealed partial class GenerateCounterBasedPasswordTest
		{
			[Fact]
			public void ThrowArgumentNullExceptionIfSecretParameterIsNull()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentNullException>(() => authenticator.GenerateCounterBasedPassword(null, 0));
			}

			[Fact]
			public void ThrowArgumentExceptionIfSecretParameterLengthIsLessThan128Bit()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateCounterBasedPassword(Secret.Substring(0, 10), 0));
			}

			[Theory]
			[InlineData(-1)]
			[InlineData(0)]
			[InlineData(3)]
			public void ThrowArgumentExceptionIfDigitsParameterIsLessThanSix(int digits)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateCounterBasedPassword(Secret, 9, digits));
			}

			[Theory]
			[InlineData(13)]
			public void ThrowArgumentExceptionIfDigitsParameterIsGreaterThanTen(int digits)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateCounterBasedPassword(Secret, 9, digits));
			}

			[Theory]
			[InlineData(AuthenticatorAlgorithm.HMACSHA256)]
			[InlineData(AuthenticatorAlgorithm.HMACSHA512)]
			[InlineData((AuthenticatorAlgorithm)5)]
			public void ThrowInvalidOperationExceptionIfAuthenticatorAlgorithmIsNotHMACSHA1(AuthenticatorAlgorithm authenticatorAlgorithm)
			{
				var authenticator = new Authenticator(options => options.AuthenticatorAlgorithm = authenticatorAlgorithm);

				Assert.Throws<InvalidOperationException>(() => authenticator.GenerateCounterBasedPassword(Secret, 9));
			}

			[Theory]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 6)]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 8)]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 10)]
			public void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInOptions(int digits, ulong iterationNumber, string expectedPassword)
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
			public void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInParameters(int digits, ulong iterationNumber, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator();
				var actualPassword = authenticator.GenerateCounterBasedPassword(Secret, iterationNumber, digits);

				Assert.Equal(expectedPassword, actualPassword);
			}

			[Theory]
			[MemberData(nameof(GetExpectedCounterBasedPasswords), 6)]
			public void GenerateCorrectSixDigitPasswordByDefaultIfDigitsParameterIsNotSpecified(int digits, ulong iterationNumber, string expectedPassword)
			{
				expectedPassword = expectedPassword.Substring(expectedPassword.Length - digits);

				var authenticator = new Authenticator();
				var actualPassword = authenticator.GenerateCounterBasedPassword(Secret, iterationNumber);

				Assert.Equal(expectedPassword, actualPassword);
			}
		}

		public sealed class GenerateSecretTest
		{
			[Theory]
			[InlineData(-5)]
			[InlineData(0)]
			[InlineData(13)]
			public void ThrowArgumentExceptionIfSizeParameterIsNotMultiplesOf40Bits(int expectedLength)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateSecret(expectedLength));
			}

			[Theory]
			[InlineData(10)]
			[InlineData(15)]
			[InlineData(20)]
			public void GenerateSecretWithCorrectLength(int expectedLength)
			{
				var authenticator = new Authenticator();
				var secret = authenticator.GenerateSecret(expectedLength);
				var actualLength = Base32.FromBase32(secret).Length;

				Assert.True(expectedLength == actualLength);
			}

			[Fact]
			public void Generate20BytesSecretByDefaultIfSizeParameterIsNotSpecified()
			{
				const int expectedLength = 20;

				var authenticator = new Authenticator();
				var secret = authenticator.GenerateSecret();
				var actualLength = Base32.FromBase32(secret).Length;

				Assert.True(expectedLength == actualLength);
			}
		}

		public sealed partial class GenerateTimeBasedPasswordTest
		{
			[Fact]
			public void ThrowArgumentNullExceptionIfSecretParameterIsNull()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentNullException>(() => authenticator.GenerateTimeBasedPassword(null));
			}

			[Fact]
			public void ThrowArgumentExceptionIfSecretParameterLengthIsLessThan128Bit()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret.Substring(0, 10)));
			}

			[Theory]
			[InlineData(-1)]
			[InlineData(0)]
			[InlineData(3)]
			public void ThrowArgumentExceptionIfDigitsParameterIsLessThanSix(int digits)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, digits));
			}

			[Fact]
			public void ThrowArgumentExceptionIfDigitsParameterIsGreaterThanTen()
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, 13));
			}

			[Theory]
			[InlineData(-1)]
			[InlineData(0)]
			public void ThrowArgumentExceptionIfTimeStepParameterIsNotPositive(int timeStep)
			{
				var authenticator = new Authenticator();

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, null, 6, timeStep));
			}

			[Fact]
			public void ThrowArgumentExceptionIfNowFuncReturnsValueLessThenAuthenticatorStartDateTime()
			{
				var authenticator = new Authenticator(options => options.StartDateTime = DateTime.UtcNow);
				var now = new DateTime(2017, 12, 16, 08, 46, 39, DateTimeKind.Utc);

				Assert.Throws<ArgumentException>(() => authenticator.GenerateTimeBasedPassword(Secret, () => now, 9));
			}

			[Fact]
			public void ThrowInvalidOperationExceptionIfAuthenticatorAlgorithmIsNotSupported()
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
			public void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInOptions(
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
			public void GenerateCorrectPasswordWithCorrectNumberOfDigitsAsSpecifiedInParameters(
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
			public void GenerateCorrectSixDigitPasswordWith30SecondsStepByDefaultIfDigitsAndTimeStepParametersAreNotSpecified(
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
