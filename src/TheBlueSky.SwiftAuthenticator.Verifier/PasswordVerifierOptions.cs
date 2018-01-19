namespace TheBlueSky.SwiftAuthenticator.Verifier
{
	public sealed class PasswordVerifierOptions
	{
		public uint NumberOfBackwardTimeSteps { get; set; } = 2;

		public uint NumberOfForwardTimeSteps { get; set; } = 2;

		public uint SynchronizationWindowSize { get; set; } = 10;
	}
}
