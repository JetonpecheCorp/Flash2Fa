namespace Flash2Fa.Internal;

internal static class Base32Codec
{
    private const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    // Table de décodage ASCII (0..127) : 255 = invalide, 254 = séparateur ignoré (' ', '-'), 0..31 = valeur
    private static ReadOnlySpan<byte> DecodeTable =>
    [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0..15
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 16..31
        254, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, // 32..47 (' '=32, '-'=45)
        255, 255,  26,  27,  28,  29,  30,  31, 255, 255, 255, 255, 255, 254, 255, 255, // 48..63 ('2'-'7'=50..55, '='=61)
        255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // 64..79 ('A'-'O')
         15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255, // 80..95 ('P'-'Z')
        255,   0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14, // 96..111 ('a'-'o')
         15,  16,  17,  18,  19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255  // 112..127 ('p'-'z')
    ];

    public static int GetEncodedLength(int byteCount) => (byteCount * 8 + 4) / 5;

    public static int GetMaxDecodedLength(int charCount) => charCount * 5 / 8;

    public static int Encode(ReadOnlySpan<byte> data, Span<char> destination)
    {
        if (data.IsEmpty)
        {
            return 0;
        }

        int charIndex = 0;
        int buffer = data[0];
        int next = 1;
        int bitsLeft = 8;

        while (bitsLeft > 0 || next < data.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < data.Length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xFF;
                    bitsLeft += 8;
                }
                else
                {
                    int pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }

            int index = 0x1F & (buffer >> (bitsLeft - 5));
            bitsLeft -= 5;
            destination[charIndex++] = Alphabet[index];
        }

        return charIndex;
    }

    public static bool TryDecode(ReadOnlySpan<char> encoded, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        if (encoded.IsEmpty)
        {
            return false;
        }

        ReadOnlySpan<byte> table = DecodeTable;
        int buffer = 0;
        int bitsLeft = 0;

        foreach (char c in encoded)
        {
            if (c >= 128)
            {
                return false;
            }

            byte val = table[c];
            if (val == 254)
            {
                continue; // Ignorer espaces, tirets et padding '='
            }

            if (val == 255)
            {
                return false; // Caractère illégal
            }

            buffer <<= 5;
            buffer |= val & 0x1F;
            bitsLeft += 5;

            if (bitsLeft >= 8)
            {
                if (bytesWritten >= destination.Length)
                {
                    return false;
                }

                destination[bytesWritten++] = (byte)(buffer >> (bitsLeft - 8));
                bitsLeft -= 8;
            }
        }

        return bytesWritten > 0;
    }
}