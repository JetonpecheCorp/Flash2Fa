# Flash2Fa

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Native AOT](https://img.shields.io/badge/Native%20AOT-100%25%20Ready-success)](#why-choose-flash2fa)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-blue)](#why-choose-flash2fa)
[![Zero Allocation](https://img.shields.io/badge/Allocation-0%20B%20Hot%20Path-orange)](#benchmarks--performance)
[![RFC 6238](https://img.shields.io/badge/RFC-6238%20%2F%204226-lightgrey)](#)

<p align="center">
  <img src="assets/logoFlash2fa.png" alt="Flash2Fa Logo" width="220" />
</p>

[English documentation](README.md)

**Flash2Fa** is a modern, ultra-fast, zero-dependency .NET library for adding Two-Factor Authentication (**2FA / TOTP**), **recovery codes**, and **native QR code generation (PNG and SVG)** to your applications.

## Table of Contents

- [Why choose Flash2Fa?](#why-choose-flash2fa)
- [Installation](#installation)
- [Quick Start (Up and running in 2 minutes)](#quick-start-up-and-running-in-2-minutes)
  - [1. Enable 2FA for a user](#1-enable-2fa-for-a-user)
  - [2. Verify the code on sign-in](#2-verify-the-code-on-sign-in)
  - [3. Use a recovery (backup) code](#3-use-a-recovery-backup-code)
- [QR Code Customization (PNG & SVG)](#qr-code-customization-png--svg)
- [Advanced Usage: Zero-Allocation Mode (`Span<T>`)](#advanced-usage-zero-allocation-mode-spant)
- [Real-World Example (.NET Minimal API)](#real-world-example-net-minimal-api)
- [API Quick Reference](#api-quick-reference)
- [Benchmarks & Performance](#benchmarks--performance)
- [Security Best Practices](#security-best-practices)

## Why choose Flash2Fa?

Implementing 2FA in .NET often forces you to stitch together multiple libraries (one for TOTP, another for QR code encoding, and `SkiaSharp` or `ImageSharp` for image rendering), which bloats your app and causes deployment headaches on **Linux, Docker, or Native AOT**.

**Flash2Fa brings everything together in a single lightweight package:**

| Advantage | What it means for your project |
| :--- | :--- |
| **Zero dependencies** | Written 100% in pure C# (HMAC, Base32, Reed-Solomon QR matrix, 1-bit PNG compression, and SVG vector paths). No native DLLs (`libSkiaSharp`, etc.) to deploy. |
| **100% Native AOT** | Zero dynamic reflection. Compiled and verified with zero warnings under `PublishAot=true` and `TrimMode=full`. |
| **Zero allocation (`0 B`)** | Hot-path operations (TOTP verification, recovery code checks, QR rendering into `Span<T>` buffers) allocate **zero bytes** on the managed heap. |
| **Zero exceptions** | Every public API follows the `Try` pattern: clear boolean return value and explicit error code (`Flash2FaError`). |
| **Safe & styled QR codes** | **SVG** or **PNG** output with custom size, colors, module shapes (`Square`, `Rounded`, `Dots`), and **automatic contrast enforcement**. |
| **Built-in crypto security** | Constant-time comparisons (SIMD-vectorized / branchless), CSPRNG via `RandomNumberGenerator`, and SHA-256 hashing for recovery codes. |

## Installation

Using the .NET CLI:

```bash
dotnet add package Flash2Fa
```

Or in your `.csproj` file:

```xml
<ItemGroup>
  <PackageReference Include="Flash2Fa" Version="1.0.0" />
</ItemGroup>
```

## Quick Start (Up and running in 2 minutes)

### 1. Enable 2FA for a user

When a user enables two-factor authentication on their account, call `TryCreateSetup` (here in **SVG**), then use `TryGenerateQrCodeBytes` if you want to serve or save the raw file directly **without Base64 encoding**:

```csharp
using Flash2Fa;

// Generates the secret key, QR code (SVG), and 8 recovery codes
if (Flash2FaService.TryCreateSetup("MyApp", "alice@example.com", out TwoFactorSetup setup, out Flash2FaError error, format: QrImageFormat.Svg))
{
    // 1. Store securely (encrypted) in your database for this user:
    string secretToStoreInDb = setup.Secret;

    // 2. Display ONCE to the user so they can write them down (e.g., "A7K9-M2P4"):
    string[] codesToShowOnce = setup.RecoveryCodes.PlainCodes;

    // 3. Store in your database (SHA-256 hashes only, never plaintext!):
    string[] hashesToStoreInDb = setup.RecoveryCodes.HashedCodes;

    // 4. Download / save the raw SVG file directly (without Base64):
    if (Flash2FaService.TryGenerateQrCodeBytes(setup.Secret, "MyApp", "alice@example.com", out byte[] svgBytes, out _, format: QrImageFormat.Svg))
    {
        File.WriteAllBytes("qrcode-2fa.svg", svgBytes);
    }
}
else
{
    Console.WriteLine($"Failed to create 2FA setup: {error}");
}
```

### 2. Verify the code on sign-in

When the user enters the 6-digit code from their authenticator app (Google Authenticator, Apple Passwords, Bitwarden, Authy, etc.):

```csharp
using Flash2Fa;

string userSecretFromDb = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
string codeTypedByUser = "482910";

// By default, allows ±30 seconds clock skew (1 step before/after)
if (Flash2FaService.VerifyCode(userSecretFromDb, codeTypedByUser, out long matchedTimeStep))
{
    // Valid code!
    // Security tip: ensure matchedTimeStep > lastUsedTimeStepFromDb
    // to prevent the same code from being replayed within the same 30s window.
    Console.WriteLine($"Sign-in authorized (time step: {matchedTimeStep})");
}
else
{
    // Invalid or expired code
    Console.WriteLine("Invalid authentication code.");
}
```

### 3. Use a recovery (backup) code

If the user lost their phone, they can enter one of their recovery codes (case-, space-, and hyphen-insensitive):

```csharp
using Flash2Fa;

string inputFromUser = "a7k9 m2p4"; // Works even in lowercase or without a hyphen
string[] userStoredHashes = GetUserRecoveryHashesFromDb();

int matchedIndex = Flash2FaService.VerifyRecoveryCode(inputFromUser, userStoredHashes);

if (matchedIndex >= 0)
{
    // Valid recovery code!
    // Immediately delete the hash at 'matchedIndex' from your database (single-use)
    RemoveRecoveryHashAt(matchedIndex);
    Console.WriteLine("Recovery sign-in succeeded!");
}
else
{
    Console.WriteLine("Invalid recovery code.");
}
```

## QR Code Customization (PNG & SVG)

Customize the QR code appearance to match your brand while ensuring guaranteed scannability:

```csharp
using Flash2Fa;

// Parse hex colors (exception-free validation)
QrColor.TryFromHex("#38BDF8", out QrColor skyBlue);
QrColor.TryFromHex("#0F172A", out QrColor darkSlate);

var options = new QrCodeOptions(
    Size: QrCodeSize.Medium,            // Small (4px/module), Medium (8px), Large (12px)
    Foreground: skyBlue,
    Background: darkSlate,
    Shape: QrModuleShape.Dots,          // Square, Rounded, or Dots
    QuietZone: 2,                       // Margin around the QR code
    EnforceReadableContrast: true       // Automatically fixes foreground if contrast is too low for cameras
);

// Export as raw SVG file (or PNG with QrImageFormat.Png)
if (Flash2FaService.TryGenerateQrCodeBytes(
    secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    issuer: "MyApp",
    accountName: "alice@example.com",
    out byte[] svgBytes,
    out Flash2FaError error,
    format: QrImageFormat.Svg,
    options: options))
{
    File.WriteAllBytes("qrcode.svg", svgBytes);
}
```

## Advanced Usage: Zero-Allocation Mode (`Span<T>`)

For high-throughput servers and real-time workloads, **Flash2Fa** writes TOTP codes and PNG/SVG files directly into your own buffers (`stackalloc` or `ArrayPool<byte>`) without allocating a single byte on the managed heap:

```csharp
using System.Buffers;
using Flash2Fa;

// 1. Generate a TOTP code on the stack (0 B allocated) — use 8 chars for TotpDigits.Eight
Span<char> codeBuffer = stackalloc char[6];
if (Flash2FaService.TryGenerateCode(secret, codeBuffer, out int charsWritten, out int remainingSeconds))
{
    ReadOnlySpan<char> code = codeBuffer[..charsWritten];
    // Use 'code' directly without allocating a string
}

// 2. Render a PNG QR code into a pooled buffer (0 B allocated)
byte[] renderBuffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
try
{
    if (Flash2FaService.TryGenerateQrCodeBytes(
        secret, "MyApp", "alice@example.com",
        destination: renderBuffer,
        out int bytesWritten,
        out Flash2FaError error,
        format: QrImageFormat.Png))
    {
        await responseStream.WriteAsync(renderBuffer.AsMemory(0, bytesWritten));
    }
}
finally
{
    ArrayPool<byte>.Shared.Return(renderBuffer);
}
```

## Real-World Example (.NET Minimal API)

Complete ASP.NET Core integration handling:
1. Enabling 2FA (`POST /2fa/enable`)
2. Direct SVG QR code file download (`GET /2fa/qrcode`) without Base64
3. Initial confirmation with replay protection (`POST /2fa/confirm`)
4. Sign-in via TOTP code or recovery code (`POST /2fa/verify`)

```csharp
using System.Runtime.InteropServices;
using Flash2Fa;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Simulated user record in database
var userStore = new UserSecurityRecord
{
    Email = "alice@example.com",
    IsTwoFactorEnabled = false
};

// STEP 1: User requests 2FA activation
app.MapPost("/2fa/enable", () =>
{
    if (!Flash2FaService.TryCreateSetup(
        issuer: "FlashBank",
        accountName: userStore.Email,
        out TwoFactorSetup setup,
        out Flash2FaError error,
        format: QrImageFormat.Svg,
        options: new QrCodeOptions(Shape: QrModuleShape.Rounded)))
    {
        return Results.BadRequest(new { Error = error.ToString() });
    }

    // Save pending secret + recovery code hashes
    userStore.PendingSecret = setup.Secret;
    userStore.RecoveryCodeHashes = [.. setup.RecoveryCodes.HashedCodes];

    return Results.Ok(new
    {
        QrCodeDownloadUrl = "/2fa/qrcode",             // Direct link to downloadable SVG file
        ManualEntryKey = setup.Secret,                 // If the user cannot scan the QR code
        RecoveryCodes = setup.RecoveryCodes.PlainCodes // Display once only!
    });
});

// STEP 1b: Direct download of the SVG QR code file (no Base64)
app.MapGet("/2fa/qrcode", () =>
{
    string? secret = userStore.PendingSecret ?? userStore.ActiveSecret;
    if (string.IsNullOrEmpty(secret))
        return Results.NotFound("No 2FA key configured.");

    if (!Flash2FaService.TryGenerateQrCodeBytes(
        secret,
        issuer: "FlashBank",
        accountName: userStore.Email,
        out byte[] svgBytes,
        out Flash2FaError error,
        format: QrImageFormat.Svg,
        options: new QrCodeOptions(Shape: QrModuleShape.Rounded)))
    {
        return Results.BadRequest(new { Error = error.ToString() });
    }

    return Results.File(svgBytes, "image/svg+xml", "qrcode-2fa.svg");
});

// STEP 2: User scans the QR code and confirms with their first TOTP code
app.MapPost("/2fa/confirm", (VerifyRequest req) =>
{
    if (string.IsNullOrEmpty(userStore.PendingSecret))
        return Results.BadRequest("No pending 2FA setup.");

    if (!Flash2FaService.VerifyCode(userStore.PendingSecret, req.Code, out long timeStep))
        return Results.Unauthorized();

    // Activate 2FA
    userStore.ActiveSecret = userStore.PendingSecret;
    userStore.PendingSecret = null;
    userStore.LastUsedTimeStep = timeStep;
    userStore.IsTwoFactorEnabled = true;

    return Results.Ok(new { Message = "Two-factor authentication enabled successfully." });
});

// STEP 3: Sign-in verification (accepts a TOTP code or a recovery code)
app.MapPost("/2fa/verify", (VerifyRequest req) =>
{
    if (!userStore.IsTwoFactorEnabled || userStore.ActiveSecret is null)
        return Results.BadRequest("2FA is not enabled.");

    // 1. Try 6-digit TOTP code
    if (Flash2FaService.VerifyCode(userStore.ActiveSecret, req.Code, out long matchedStep))
    {
        // Replay protection: reject any code from the same or an earlier time step
        if (matchedStep <= userStore.LastUsedTimeStep)
            return Results.Unauthorized();

        userStore.LastUsedTimeStep = matchedStep;
        return Results.Ok(new { Authenticated = true, Method = "TOTP" });
    }

    // 2. Otherwise, try a recovery code with zero allocation via AsSpan
    int recoveryIdx = Flash2FaService.VerifyRecoveryCode(req.Code, CollectionsMarshal.AsSpan(userStore.RecoveryCodeHashes));
    if (recoveryIdx >= 0)
    {
        // Immediately invalidate the used recovery code (single-use)
        userStore.RecoveryCodeHashes.RemoveAt(recoveryIdx);
        return Results.Ok(new
        {
            Authenticated = true,
            Method = "RecoveryCode",
            RemainingRecoveryCodes = userStore.RecoveryCodeHashes.Count
        });
    }

    return Results.Unauthorized();
});

app.Run();

record VerifyRequest(string Code);

class UserSecurityRecord
{
    public string Email { get; set; } = "";
    public bool IsTwoFactorEnabled { get; set; }
    public string? PendingSecret { get; set; }
    public string? ActiveSecret { get; set; }
    public long LastUsedTimeStep { get; set; }
    public List<string> RecoveryCodeHashes { get; set; } = [];
}
```

## API Quick Reference

All methods are exposed on the static `Flash2FaService` class:

| Method | Purpose |
| :--- | :--- |
| `TryCreateSetup(...)` | Generates the Base32 secret, QR code (Base64), and recovery codes in a single call. |
| `VerifyCode(...)` | Validates a 6- or 8-digit TOTP code with clock-skew tolerance and outputs the matched time step. |
| `TryGenerateCode(...)` | Computes the current TOTP code (and remaining seconds) as a `string` or into a `Span<char>`. |
| `TryGenerateQrCodeBase64(...)` | Generates a PNG or SVG QR code ready for HTML (`data:image/...;base64,`). |
| `TryGenerateQrCodeBytes(...)` | Generates raw PNG or SVG bytes (allocates `byte[]` or writes directly into `Span<byte>`). |
| `TryGenerateRecoveryCodes(...)` / `GenerateRecoveryCodes()` | Generates 1 to 64 readable recovery codes (8 by default, `XXXX-XXXX`) and their SHA-256 hashes. |
| `VerifyRecoveryCode(...)` | Verifies a recovery code in constant time against one hash or a list of hashes. |
| `IsValidSecret(...)` | Checks whether a Base32 secret is syntactically valid and long enough. |

## Benchmarks & Performance

Measured with **BenchmarkDotNet** on **.NET 10.0** (Release):

| Method | Mean | Throughput (1 core) | Allocated |
| :--- | :---: | :---: | :---: |
| **`Recovery: VerifyCode (8 hashes)`** | **256.2 ns** | ~3,900,000 ops/s | **0 B** (`-`) |
| **`TOTP: TryGenerateCode (Span)`** | **692.7 ns** | ~1,440,000 ops/s | **0 B** (`-`) |
| **`TOTP: VerifyCode (Hot Path)`** | **1,942.8 ns** | ~514,000 ops/s | **0 B** (`-`) |
| **`QR Code: PNG 1-bit (Span)`** | **142.2 µs** | ~7,030 QR/s | **0 B** (`-`) |
| **`QR Code: SVG Custom Dots (Span)`** | **145.2 µs** | ~6,880 QR/s | **0 B** (`-`) |
| **`Setup: CreateSetup Complet (PNG + 8 Recovery)`** | **165.2 µs** | ~6,050 setups/s | **2,096 B** *(returned objects)* |

### Understanding these numbers

* **`0 B` (`-`) across all 5 hot-path operations:** When a user signs in (`VerifyCode`), uses a recovery code, or your server renders a QR code into a buffer, **not a single byte is allocated on the heap**. Your web servers experience zero GC pressure even under heavy load.
* **256 nanoseconds to verify 8 recovery codes:** Normalizing user input, computing its SHA-256 digest, and comparing all 8 hashes in constant time takes a quarter of a microsecond.
* **~0.14 milliseconds for a full QR code:** `otpauth://` URI encoding, Reed-Solomon error-correction coding, evaluating all 8 ISO masks, and Zlib PNG compression (or SVG path generation) all run in under one-sixth of a millisecond in pure C#.
* **`2,096 B` on `TryCreateSetup`:** Only the final returned objects for your application (the Base64 QR code string and the two 8-element `string[]` arrays for recovery codes).

## Security Best Practices

1. **Never store recovery codes in plaintext:** Only persist `setup.RecoveryCodes.HashedCodes` (the SHA-256 hashes) in your database and delete each hash immediately after use.
2. **Protect the secret key at rest:** Encrypt `setup.Secret` before storing it in your user table (e.g., with ASP.NET Core Data Protection or AES-GCM).
3. **Prevent TOTP code replay (Anti-Replay):** A TOTP code is valid for 30 seconds. Store the `matchedTimeStep` returned by `VerifyCode` and reject any attempt where `matchedTimeStep <= lastUsedTimeStep`.
4. **Apply rate limiting:** Protect your `/2fa/verify` endpoint against brute-force attempts (e.g., max 5 attempts per minute per account).
