using System;

namespace TheBlueSky.SwiftAuthenticator.Verifier
{
	public sealed class PasswordVerifier
	{
		private readonly Authenticator authenticator;
		private readonly PasswordVerifierOptions options = new PasswordVerifierOptions();

		public PasswordVerifier(Authenticator authenticator, Action<PasswordVerifierOptions> setupAction = null)
		{
			this.authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));
			setupAction?.Invoke(this.options);
		}

		public uint NumberOfFutureTimeSteps => this.options.NumberOfForwardTimeSteps;

		public uint NumberOfPastTimeSteps => this.options.NumberOfBackwardTimeSteps;

		public uint SynchronizationWindowSize => this.options.SynchronizationWindowSize;

		public (bool IsVerified, ulong SynchronizationValue) VerifyCounterBasedPassword(string password, string secret, ulong iterationNumber, int digits = 6)
		{
			for (var iteration = iterationNumber; iteration < iterationNumber + this.SynchronizationWindowSize; ++iteration)
			{
				var hotp = this.authenticator.GenerateCounterBasedPassword(secret, iteration, digits);

				if (password == hotp)
				{
					return (true, iteration);
				}
			}

			return (false, iterationNumber);
		}

		public (bool IsVerified, int TimeStepDrift) VerifyTimeBasedPassword(string password, string secret, Func<DateTime> nowFunc = null)
		{
			var timeStep = this.authenticator.SizeOfTimeStep;
			var now = nowFunc == null ? DateTime.UtcNow : nowFunc();

			for (var i = -this.options.NumberOfBackwardTimeSteps; i <= this.options.NumberOfForwardTimeSteps; ++i)
			{
				var time = now.AddSeconds(timeStep * i);

				var totp = this.authenticator.GenerateTimeBasedPassword(secret, () => time);
				var isEqual = password == totp;

				if (isEqual)
				{
					return (isEqual, Convert.ToInt32(i));
				}
			}

			return (false, 0);
		}
	}
}
