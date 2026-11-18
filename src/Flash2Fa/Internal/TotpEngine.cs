using System.Buffers.Binary;
using System.Security.Cryptography;

namespace Flash2Fa.Internal;

internal static class TotpEngine
{
    public const int DefaultSecretByteLength = 20; // 160 bits -> 32 chars Base32
    public const int TimeStepSeconds = 30;
    private const int MaxSecretBytes = 128;

    public static string GenerateSecret()
    {
        Span<byte> randomBytes = stackalloc byte[DefaultSecretByteLength];
        RandomNumberGenerator.Fill(randomBytes);

        return string.Create(Base32Codec.GetEncodedLength(DefaultSecretByteLength), randomBytes, static (span, bytes) =>
        {
            Base32Codec.Encode(bytes, span);
        });
    }

    public static bool IsValidSecret(ReadOnlySpan<char> secret)
    {
        if (secret.IsEmpty || secret.Length > 256)
        {
            return false;
        }

        Span<byte> buffer = stackalloc byte[MaxSecretBytes];
        return Base32Codec.TryDecode(secret, buffer, out int bytesWritten) && bytesWritten >= 10;
    }

    public static bool TryGenerateCode(
        ReadOnlySpan<char> secret,
        Span<char> destination,
        out int charsWritten,
        out int remainingSeconds,
        DateTimeOffset? timestamp = null,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        charsWritten = 0;
        remainingSeconds = 0;

        int digitCount = (int)digits;
        if (destination.Length < digitCount || secret.IsEmpty || secret.Length > 256)
        {
            return false;
        }

        Span<byte> secretBytes = stackalloc byte[MaxSecretBytes];
        if (!Base32Codec.TryDecode(secret, secretBytes, out int secretLength) || secretLength == 0)
        {
            return false;
        }

        long unixSeconds = timestamp.HasValue
            ? timestamp.Value.ToUnixTimeSeconds()
            : (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerSecond;
        long timeStep = FloorDiv(unixSeconds, TimeStepSeconds);
        remainingSeconds = TimeStepSeconds - (int)PositiveModulo(unixSeconds, TimeStepSeconds);

        ComputeCodeForStep(secretBytes[..secretLength], timeStep, algorithm, digitCount, destination[..digitCount]);
        charsWritten = digitCount;
        return true;
    }

    public static bool VerifyCode(
        ReadOnlySpan<char> secret,
        ReadOnlySpan<char> userCode,
        out long matchedTimeStep,
        int toleranceSteps = 1,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        matchedTimeStep = 0;
        int digitCount = (int)digits;

        if (toleranceSteps < 0 || toleranceSteps > 10 || secret.IsEmpty || secret.Length > 256)
        {
            return false;
        }

        userCode = userCode.Trim();
        if (userCode.Length != digitCount)
        {
            return false;
        }

        int userOtp = 0;
        for (int i = 0; i < userCode.Length; i++)
        {
            uint d = (uint)(userCode[i] - '0');
            if (d > 9)
            {
                return false;
            }
            userOtp = userOtp * 10 + (int)d;
        }

        Span<byte> secretBytes = stackalloc byte[MaxSecretBytes];
        if (!Base32Codec.TryDecode(secret, secretBytes, out int secretLength) || secretLength == 0)
        {
            return false;
        }

        ReadOnlySpan<byte> key = secretBytes[..secretLength];
        long unixSeconds = (DateTime.UtcNow.Ticks - DateTime.UnixEpoch.Ticks) / TimeSpan.TicksPerSecond;
        long currentStep = FloorDiv(unixSeconds, TimeStepSeconds);

        bool isValid = false;

        for (int offset = -toleranceSteps; offset <= toleranceSteps; offset++)
        {
            long candidateStep = currentStep + offset;
            int expectedOtp = ComputeOtpIntForStep(key, candidateStep, algorithm, digitCount);

            uint diff = (uint)(userOtp ^ expectedOtp);
            if ((((diff - 1) & ~diff) >> 31) != 0)
            {
                isValid = true;
                matchedTimeStep = candidateStep;
            }
        }

        return isValid;
    }

    private static void ComputeCodeForStep(
        ReadOnlySpan<byte> secretKey,
        long timeStep,
        TotpAlgorithm algorithm,
        int digitCount,
        Span<char> destination)
    {
        int otp = ComputeOtpIntForStep(secretKey, timeStep, algorithm, digitCount);

        for (int i = digitCount - 1; i >= 0; i--)
        {
            destination[i] = (char)('0' + (otp % 10));
            otp /= 10;
        }
    }

    private static int ComputeOtpIntForStep(
        ReadOnlySpan<byte> secretKey,
        long timeStep,
        TotpAlgorithm algorithm,
        int digitCount)
    {
        Span<byte> counterBytes = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(counterBytes, timeStep);

        Span<byte> hashBuffer = stackalloc byte[64];

#pragma warning disable CA5350 // HMAC-SHA1 est requis par la norme RFC 6238 pour la compatibilité Authenticator
        int hashLength = algorithm switch
        {
            TotpAlgorithm.Sha1 => HMACSHA1.HashData(secretKey, counterBytes, hashBuffer),
            TotpAlgorithm.Sha256 => HMACSHA256.HashData(secretKey, counterBytes, hashBuffer),
            TotpAlgorithm.Sha512 => HMACSHA512.HashData(secretKey, counterBytes, hashBuffer),
            _ => HMACSHA1.HashData(secretKey, counterBytes, hashBuffer)
        };
#pragma warning restore CA5350

        int modulo = digitCount == 8 ? 100_000_000 : 1_000_000;
        return DynamicTruncate(hashBuffer[..hashLength], modulo);
    }

    private static int DynamicTruncate(ReadOnlySpan<byte> hash, int modulo)
    {
        // Dynamic Truncation (RFC 4226 Section 5.4)
        int offset = hash[^1] & 0x0F;
        int binaryCode =
            ((hash[offset] & 0x7F) << 24) |
            ((hash[offset + 1] & 0xFF) << 16) |
            ((hash[offset + 2] & 0xFF) << 8) |
            (hash[offset + 3] & 0xFF);

        return binaryCode % modulo;
    }

    private static long FloorDiv(long a, long b)
    {
        long q = a / b;
        long r = a % b;
        if ((r != 0) && ((r < 0) != (b < 0)))
        {
            q--;
        }
        return q;
    }

    private static long PositiveModulo(long a, long b)
    {
        long r = a % b;
        return r < 0 ? r + b : r;
    }
}