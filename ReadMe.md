# HOTP and TOTP Library for .NET #

## What is it? ##

`TheBlueSky.SwiftAuthenticator` is a .NET implementation of HMAC-Based One-Time Password (HOTP) and Time-Based One-Time Password (TOTP) algorithms as described in [RFC 4226](https://tools.ietf.org/html/rfc4226) and [RFC 6238](https://tools.ietf.org/html/rfc6238) respectively.

## How to get it? ##

To install `TheBlueSky.SwiftAuthenticator`, run the following command in the Package Manager Console:

`Install-Package TheBlueSky.SwiftAuthenticator`

Or search for `TheBlueSky.SwiftAuthenticator` in NuGet Package Manager.

## Usage ##

The simplest way to get started is to use the API with the default parameters:

1. Create an instance of `Authenticator`:

```csharp
var authenticator = new Authenticator();
```

2. Generate a secret (will generate a `Base32` encoded 20-byte secret):

```csharp
var secret = authenticator.GenerateSecret();
```

3. Generate a password from the secret (will generate a 6-digit HOTP using the provided iteration and 6-digit TOTP using the current UTC time and 30-second step):

```csharp
// HMAC-Based One-Time Password (HOTP)
var hotp = authenticator.GenerateCounterBasedPassword(secret, 28091977);

// Time-Based One-Time Password (TOTP)
var totp = authenticator.GenerateTimeBasedPassword(secret);
```

## Supported Frameworks ##

This library targets [.NET Standard 2.0](https://docs.microsoft.com/en-us/dotnet/standard/net-standard); hence, it can be referenced from applications and libraries that target .NET Standard 2.0 or any of the supported platforms:

* .NET Core 2.0
* .NET Framework 4.6.1
* Mono 5.4
* Universal Windows Platform 10.0.16299
* Xamarin.Android 8.0
* Xamarin.iOS 10.14
* Xamarin.Mac 3.8
