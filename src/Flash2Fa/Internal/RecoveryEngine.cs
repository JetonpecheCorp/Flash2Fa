using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Security.Cryptography;

namespace Flash2Fa.Internal;

internal static class RecoveryEngine
{
    // 32 caractères sans ambiguïté visuelle (exclusion de 0, O, 1, I)
    private const string Alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    private const int CodeRawLength = 8; // 8 caractères -> format "XXXX-XXXX" (9 chars)
    private const int MaxNormalizedLength = 32;

    public static bool TryGenerate(int count, out RecoveryCodes codes)
    {
        if (count is < 1 or > 64)
        {
            codes = default;
            return false;
        }

        string[] plainCodes = new string[count];
        string[] hashedCodes = new string[count];

        Span<byte> allRandomBytes = stackalloc byte[count * CodeRawLength];
        RandomNumberGenerator.Fill(allRandomBytes);

        Span<byte> rawAscii = stackalloc byte[CodeRawLength];
        Span<byte> hashBuffer = stackalloc byte[32];

        for (int i = 0; i < count; i++)
        {
            ReadOnlySpan<byte> randomBytes = allRandomBytes.Slice(i * CodeRawLength, CodeRawLength);

            for (int j = 0; j < CodeRawLength; j++)
            {
                // 256 est un multiple exact de 32 (8 * 32 = 256) : zéro biais modulo !
                char c = Alphabet[randomBytes[j] & 0x1F];
                rawAscii[j] = (byte)c;
            }

            // Formatage "XXXX-XXXX"
            plainCodes[i] = string.Create(9, rawAscii, static (span, ascii) =>
            {
                span[0] = (char)ascii[0];
                span[1] = (char)ascii[1];
                span[2] = (char)ascii[2];
                span[3] = (char)ascii[3];
                span[4] = '-';
                span[5] = (char)ascii[4];
                span[6] = (char)ascii[5];
                span[7] = (char)ascii[6];
                span[8] = (char)ascii[7];
            });

            // Calcul du hash SHA-256 en hexadécimal minuscule
            SHA256.HashData(rawAscii, hashBuffer);
            hashedCodes[i] = Convert.ToHexStringLower(hashBuffer);
        }

        codes = new RecoveryCodes(plainCodes, hashedCodes);
        return true;
    }

    public static bool VerifyCode(ReadOnlySpan<char> userInputCode, ReadOnlySpan<char> storedHash)
    {
        if (storedHash.Length != 64 || userInputCode.IsEmpty || userInputCode.Length > 64)
        {
            return false;
        }

        Span<byte> normalizedAscii = stackalloc byte[MaxNormalizedLength];
        if (!TryNormalizeCode(userInputCode, normalizedAscii, out int normalizedLength))
        {
            return false;
        }

        Span<byte> expectedHashBytes = stackalloc byte[32];
        if (Convert.FromHexString(storedHash, expectedHashBytes, out _, out int bytesWritten) != System.Buffers.OperationStatus.Done || bytesWritten != 32)
        {
            return false;
        }

        Span<byte> computedHashBytes = stackalloc byte[32];
        SHA256.HashData(normalizedAscii[..normalizedLength], computedHashBytes);

        return CryptographicOperations.FixedTimeEquals(computedHashBytes, expectedHashBytes);
    }

    public static int VerifyCode(ReadOnlySpan<char> userInputCode, ReadOnlySpan<string> storedHashes)
    {
        if (storedHashes.IsEmpty || userInputCode.IsEmpty || userInputCode.Length > 64)
        {
            return -1;
        }

        Span<byte> normalizedAscii = stackalloc byte[MaxNormalizedLength];
        if (!TryNormalizeCode(userInputCode, normalizedAscii, out int normalizedLength))
        {
            return -1;
        }

        Span<byte> computedHashBytes = stackalloc byte[32];
        SHA256.HashData(normalizedAscii[..normalizedLength], computedHashBytes);

        // Encodage hexadécimal minuscule une seule fois sur la pile (64 chars = 128 octets)
        Span<char> computedHexChars = stackalloc char[64];
        Convert.TryToHexStringLower(computedHashBytes, computedHexChars, out _);
        ReadOnlySpan<byte> computedUtf16Bytes = MemoryMarshal.AsBytes(computedHexChars);

        int matchedIndex = -1;

        for (int i = 0; i < storedHashes.Length; i++)
        {
            string? hash = storedHashes[i];
            if (hash is null || hash.Length != 64)
            {
                continue;
            }

            ReadOnlySpan<byte> candidateUtf16Bytes = MemoryMarshal.AsBytes(hash.AsSpan());
            if (ConstantTimeEquals128(computedUtf16Bytes, candidateUtf16Bytes))
            {
                matchedIndex = i;
            }
        }

        return matchedIndex;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static bool ConstantTimeEquals128(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        if (Vector256.IsHardwareAccelerated)
        {
            ref byte ra = ref MemoryMarshal.GetReference(a);
            ref byte rb = ref MemoryMarshal.GetReference(b);
            Vector256<byte> v0 = Vector256.LoadUnsafe(ref ra) ^ Vector256.LoadUnsafe(ref rb);
            Vector256<byte> v1 = Vector256.LoadUnsafe(ref ra, 32) ^ Vector256.LoadUnsafe(ref rb, 32);
            Vector256<byte> v2 = Vector256.LoadUnsafe(ref ra, 64) ^ Vector256.LoadUnsafe(ref rb, 64);
            Vector256<byte> v3 = Vector256.LoadUnsafe(ref ra, 96) ^ Vector256.LoadUnsafe(ref rb, 96);
            return (v0 | v1 | v2 | v3) == Vector256<byte>.Zero;
        }

        ulong acc = 0;
        ReadOnlySpan<ulong> ua = MemoryMarshal.Cast<byte, ulong>(a);
        ReadOnlySpan<ulong> ub = MemoryMarshal.Cast<byte, ulong>(b);
        for (int i = 0; i < 16; i++)
        {
            acc |= ua[i] ^ ub[i];
        }
        return acc == 0;
    }

    private static bool TryNormalizeCode(ReadOnlySpan<char> input, Span<byte> destination, out int length)
    {
        length = 0;

        foreach (char c in input)
        {
            // Ignorer les tirets et espaces saisis par l'utilisateur
            if (c is '-' or ' ')
            {
                continue;
            }

            if (length >= destination.Length)
            {
                return false;
            }

            // Conversion majuscule ASCII rapide
            char upper = (uint)(c - 'a') <= ('z' - 'a') ? (char)(c - 32) : c;

            // Vérifier que c'est bien un caractère alphanumérique ASCII imprimable
            if (upper is < '0' or > 'Z' or (> '9' and < 'A'))
            {
                return false;
            }

            destination[length++] = (byte)upper;
        }

        return length == CodeRawLength;
    }
}