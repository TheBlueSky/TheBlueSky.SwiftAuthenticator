using System;

using Xunit;

namespace TheBlueSky.SwiftAuthenticator.Verifier.Test
{
	public static partial class PasswordVerifierTest
	{
		public static class PasswordVerifierConstructorTest
		{
			[Fact]
			public static void ThrowArgumentNullExceptionIfAuthenticatorParameterIsNull()
			{
				Assert.Throws<ArgumentNullException>(() => new PasswordVerifier(null));
			}

			[Fact]
			public static void PropertiesAreSetToTheirDefaultValueIfOptionsParameterIsNotSet()
			{
				const uint defaultSynchronizationWindowSize = 10;
				const uint defaultNumberOfBackwardTimeSteps = 2;
				const uint defaultNumberOfForwardTimeSteps = 2;

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);

				Assert.Equal(defaultSynchronizationWindowSize, verifier.SynchronizationWindowSize);
				Assert.Equal(defaultNumberOfBackwardTimeSteps, verifier.NumberOfPastTimeSteps);
				Assert.Equal(defaultNumberOfForwardTimeSteps, verifier.NumberOfFutureTimeSteps);
			}

			[Fact]
			public static void PropertiesAreSetCorrectlyAsSpecifiedInPasswordVerifierOptionsAction()
			{
				const uint synchronizationWindowSize = 9;
				const uint numberOfBackwardTimeSteps = 3;
				const uint numberOfForwardTimeSteps = 5;

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator, options =>
				{
					options.SynchronizationWindowSize = synchronizationWindowSize;
					options.NumberOfBackwardTimeSteps = numberOfBackwardTimeSteps;
					options.NumberOfForwardTimeSteps = numberOfForwardTimeSteps;
				});

				Assert.Equal(synchronizationWindowSize, verifier.SynchronizationWindowSize);
				Assert.Equal(numberOfBackwardTimeSteps, verifier.NumberOfPastTimeSteps);
				Assert.Equal(numberOfForwardTimeSteps, verifier.NumberOfFutureTimeSteps);
			}
		}

		public static class VerifyCounterBasedPasswordTest
		{
			[Theory]
			[InlineData("287082", 1)]
			[InlineData("359152", 2)]
			[InlineData("338314", 4)]
			[InlineData("162583", 7)]
			[InlineData("520489", 9)]
			public static void SuccessfullyVerifyPasswordGeneratedForTheSpecifiedIterationNumber(string password, ulong iterationNumber)
			{
				var secret = "12345678901234567890";

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);
				var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(password, secret, iterationNumber);

				Assert.True(isVerified && synchronizationValue == iterationNumber);
			}

			[Theory]
			[InlineData("287082", 1)]
			[InlineData("359152", 2)]
			[InlineData("338314", 4)]
			[InlineData("162583", 7)]
			[InlineData("520489", 9)]
			public static void SuccessfullyVerifyPasswordGeneratedWithinTheDefaultSynchronizationWindow(string password, ulong iterationNumber)
			{
				var secret = "12345678901234567890";
				var counterValue = 0uL; // 0 is not one of the input values for iterationNumber

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);
				var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(password, secret, counterValue);

				Assert.True(isVerified && synchronizationValue == iterationNumber);
			}

			[Theory]
			[InlineData("162583", 7)]
			[InlineData("520489", 9)]
			[InlineData("403154", 10)]
			[InlineData("481090", 11)]
			[InlineData("868912", 12)]
			public static void SuccessfullyVerifyPasswordGeneratedWithinTheConfiguredSynchronizationWindow(string password, ulong iterationNumber)
			{
				var secret = "12345678901234567890";
				var counterValue = 0uL; // 0 is not one of the input values for iterationNumber

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator, options => options.SynchronizationWindowSize = 13);
				var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(password, secret, counterValue);

				Assert.True(isVerified && synchronizationValue == iterationNumber);
			}

			[Theory]
			[InlineData("403154")] // 10
			[InlineData("868912")] // 12
			public static void FailToVerifyPasswordGeneratedOutsideTheDefaultSynchronizationWindow(string password)
			{
				var secret = "12345678901234567890";
				var counterValue = 0uL;

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);
				var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(password, secret, counterValue);

				Assert.False(isVerified);
			}

			[Theory]
			[InlineData("162583")] // 7
			[InlineData("520489")] // 9
			public static void FailToVerifyPasswordGeneratedOutsideTheConfiguredSynchronizationWindow(string password)
			{
				var secret = "12345678901234567890";
				var counterValue = 0uL;

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator, options => options.SynchronizationWindowSize = 7);
				var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(password, secret, counterValue);

				Assert.False(isVerified);
			}

			[Fact]
			public static void FailToVerifyPasswordGeneratedForAnIterationBeforeTheCounterValue()
			{
				var password = "162583"; // iterationNumber = 7
				var secret = "12345678901234567890";
				var counterValue = 9uL;

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);
				var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(password, secret, counterValue);

				Assert.False(isVerified);
			}
		}

		public static class VerifyTimeBasedPasswordTest
		{
			[Theory]
			[InlineData("186057", -2)]
			[InlineData("980357", -1)]
			[InlineData("005924", 00)]
			[InlineData("590587", +1)]
			[InlineData("240500", +2)]
			public static void SuccessfullyVerifyPasswordGeneratedWithinTheServerTimeStepOrTheDefaultBackwardAndForwardTimeSteps(string password, int drift)
			{
				var secret = "12345678901234567890";
				var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				var now = unixEpoch.AddSeconds(1234567890);

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);
				var (isVerified, timeStepDrift) = verifier.VerifyTimeBasedPassword(password, secret, () => now);

				Assert.True(isVerified && timeStepDrift == drift);
			}

			[Theory]
			[InlineData(3, 0, "798045", -3)]
			[InlineData(0, 3, "992085", +3)]
			public static void SuccessfullyVerifyPasswordGeneratedWithinTheServerTimeStepOrTheConfiguredBackwardAndForwardTimeSteps(uint backStep, uint foreStep, string password, int drift)
			{
				var secret = "12345678901234567890";
				var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				var now = unixEpoch.AddSeconds(1234567890);

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator, options =>
				{
					options.NumberOfBackwardTimeSteps = backStep;
					options.NumberOfForwardTimeSteps = foreStep;
				});
				var (isVerified, timeStepDrift) = verifier.VerifyTimeBasedPassword(password, secret, () => now);

				Assert.True(isVerified && timeStepDrift == drift);
			}

			[Theory]
			[InlineData("798045")] // -3
			[InlineData("992085")] // +3
			public static void FailToVerifyPasswordGeneratedOutsideTheServerTimeStepAndTheDefaultBackwardAndForwardTimeSteps(string password)
			{
				var secret = "12345678901234567890";
				var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				var now = unixEpoch.AddSeconds(1234567890);

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator);
				var (isVerified, timeStepDrift) = verifier.VerifyTimeBasedPassword(password, secret, () => now);

				Assert.False(isVerified);
			}

			[Theory]
			[InlineData(0, 2, "798045")] // -3
			[InlineData(2, 0, "992085")] // +3
			public static void FailToVerifyPasswordGeneratedOutsideTheServerTimeStepAndTheConfiguredBackwardAndForwardTimeSteps(uint backStep, uint foreStep, string password)
			{
				var secret = "12345678901234567890";
				var unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
				var now = unixEpoch.AddSeconds(1234567890);

				var authenticator = new Authenticator();
				var verifier = new PasswordVerifier(authenticator, options =>
				{
					options.NumberOfBackwardTimeSteps = backStep;
					options.NumberOfForwardTimeSteps = foreStep;
				});
				var (isVerified, timeStepDrift) = verifier.VerifyTimeBasedPassword(password, secret, () => now);

				Assert.False(isVerified);
			}
		}
	}
}
