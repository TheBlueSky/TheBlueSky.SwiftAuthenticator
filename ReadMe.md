# HOTP and TOTP Library for .NET #

## What is it? ##

`TheBlueSky.SwiftAuthenticator` is a .NET implementation of HMAC-Based One-Time Password (HOTP) and Time-Based One-Time Password (TOTP) algorithms as described in [RFC 4226](https://tools.ietf.org/html/rfc4226) and [RFC 6238](https://tools.ietf.org/html/rfc6238) respectively.

The repository contains 2 libraries:

1. `TheBlueSky.SwiftAuthenticator`: This library contains the types and methods needed to generate secrets and passwords. It is used by both, the client (prover) and the server (verifier).

2. `TheBlueSky.SwiftAuthenticator.Verifier`: This library contains the types and methods needed to verify passwords. It is used by the server (verifier).

## How to get it? ##

1. To install `TheBlueSky.SwiftAuthenticator`, run the following command in the Package Manager Console:

```powershell
Install-Package TheBlueSky.SwiftAuthenticator
```

2. To install `TheBlueSky.SwiftAuthenticator.Verifier`, run the following command in the Package Manager Console:

```powershell
Install-Package TheBlueSky.SwiftAuthenticator.Verifier
```

Or search for `TheBlueSky.SwiftAuthenticator` and `TheBlueSky.SwiftAuthenticator.Verifier` in NuGet Package Manager.

## Usage ##

The simplest way to get started is to use the API with the default parameters:

### Generate password ###

1. Generate a secret (will generate a `Base32` encoded 20-byte secret):

```csharp
var secret = Authenticator.GenerateSecret();
```

2. Create an instance of `Authenticator`:

```csharp
var authenticator = new Authenticator();
```

3. Generate a password from the secret (will generate a 6-digit HOTP using the provided iteration and 6-digit TOTP using the current UTC time and 30-second time step):

```csharp
// HMAC-Based One-Time Password (HOTP)
var hotp = authenticator.GenerateCounterBasedPassword(secret, 28091977);

// Time-Based One-Time Password (TOTP)
var totp = authenticator.GenerateTimeBasedPassword(secret);
```

### Verify password ###

1. Create an instance of `Authenticator`:

```csharp
var authenticator = new Authenticator();
```

2. Create an instance of `PasswordVerifier`:

```csharp
var verifier = new PasswordVerifier(authenticator);
```

3. Verify password (will successfully verify passwords generated with the default values):

```csharp
// HMAC-Based One-Time Password (HOTP)
var (isVerified, synchronizationValue) = verifier.VerifyCounterBasedPassword(hotp, secret, 28091977);

// Time-Based One-Time Password (TOTP)
var (isVerified, timeStepDrift) = verifier.VerifyTimeBasedPassword(totp, secret); // assuming totp is generated within the 30-second time step
```

## Supported Frameworks ##

Both the libraries target .NET Standard 1.3 and .NET Standard 2.0 (read about .NET Standard [here](https://docs.microsoft.com/en-us/dotnet/standard/net-standard)); hence, they can be referenced from libraries that target .NET Standard 1.3 and above, and applications that target any of the supported platforms:

* .NET Core 1.0 and above
* .NET Framework 4.6 and above
* Mono 4.6 and above
* Universal Windows Platform 10.0 and above
* Xamarin.Android 8.0 and above
* Xamarin.iOS 10.0 and above
* Xamarin.Mac 3.0 and above
