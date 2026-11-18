using System.Runtime.CompilerServices;

namespace Flash2Fa.Internal;

/// <summary>
/// Représente une matrice QR Code calculée entièrement sur la pile (zéro allocation).
/// Stocke 1 octet par module (0 = clair, 1 = foncé) pour un accès O(1) sans décalage de bits.
/// </summary>
internal readonly ref struct QrMatrix
{
    private readonly Span<byte> _modules;
    public int Size { get; }

    public QrMatrix(int size, Span<byte> buffer)
    {
        Size = size;
        _modules = buffer;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public bool GetModule(int x, int y) => _modules[y * Size + x] != 0;

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public ReadOnlySpan<byte> GetRow(int y) => _modules.Slice(y * Size, Size);
}

internal static class QrMatrixBuilder
{
    public const int MaxVersion = 10;
    public const int MaxGridSize = 17 + MaxVersion * 4; // 57x57
    public const int RequiredBufferSize = MaxGridSize * MaxGridSize; // 3 249 octets

    // Capacité en octets (Mode Byte, Niveau L) pour Versions 1 à 10
    private static ReadOnlySpan<short> ByteCapacitiesL => [0, 17, 32, 53, 78, 106, 134, 154, 192, 230, 271];

    // Total de codewords (données + ECC) par version
    private static ReadOnlySpan<short> TotalCodewords => [0, 26, 44, 70, 100, 134, 172, 196, 242, 292, 346];

    // Nombre de codewords ECC par bloc (Niveau L)
    private static ReadOnlySpan<byte> EccPerBlockL => [0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18];

    // Nombre de blocs de correction d'erreur (Niveau L)
    private static ReadOnlySpan<byte> NumBlocksL => [0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4];

    // Bits d'information de format pré-calculés (Niveau L + Masques 0..7) avec masque 0x5412
    private static ReadOnlySpan<ushort> FormatInfoL =>
    [
        0x77C4, 0x72F3, 0x7DAA, 0x789D, 0x662F, 0x6318, 0x6C41, 0x6976
    ];

    // Bits d'information de version pré-calculés (Versions 7 à 10)
    private static ReadOnlySpan<uint> VersionInfo => [0x07C94, 0x085BC, 0x09A99, 0x0A4D3];

    // Table exponentielle doublée (512 octets) dans GF(256) -> évite le modulo 255 dans la boucle Reed-Solomon
    private static ReadOnlySpan<byte> GfExp =>
    [
        1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38,
        76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192,
        157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35,
        70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
        95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240,
        253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226,
        217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206,
        129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204,
        133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84,
        168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115,
        230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255,
        227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65,
        130, 25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166,
        81, 162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9,
        18, 36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22,
        44, 88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1,
        2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38, 76,
        152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192, 157,
        39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35, 70,
        140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161, 95,
        190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240, 253,
        231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226, 217,
        175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206, 129,
        31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204, 133,
        23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84, 168,
        77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115, 230,
        209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255, 227,
        219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130,
        25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81,
        162, 89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18,
        36, 72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44,
        88, 176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1, 0
    ];

    private static ReadOnlySpan<byte> GfLog =>
    [
        0, 0, 1, 25, 2, 50, 26, 198, 3, 223, 51, 238, 27, 104, 199, 75,
        4, 100, 224, 14, 52, 141, 239, 129, 28, 193, 105, 248, 200, 8, 76, 113,
        5, 138, 101, 47, 225, 36, 15, 33, 53, 147, 142, 218, 240, 18, 130, 69,
        29, 181, 194, 125, 106, 39, 249, 185, 201, 154, 9, 120, 77, 228, 114, 166,
        6, 191, 139, 98, 102, 221, 48, 253, 226, 152, 37, 179, 16, 145, 34, 136,
        54, 208, 148, 206, 143, 150, 219, 189, 241, 210, 19, 92, 131, 56, 70, 64,
        30, 66, 182, 163, 195, 72, 126, 110, 107, 58, 40, 84, 250, 133, 186, 61,
        202, 94, 155, 159, 10, 21, 121, 43, 78, 212, 229, 172, 115, 243, 167, 87,
        7, 112, 192, 247, 140, 128, 99, 13, 103, 74, 222, 237, 49, 197, 254, 24,
        227, 165, 153, 119, 38, 184, 180, 124, 17, 68, 146, 217, 35, 32, 137, 46,
        55, 63, 209, 91, 149, 188, 207, 205, 144, 135, 151, 178, 220, 252, 190, 97,
        242, 86, 211, 171, 20, 42, 93, 158, 132, 60, 57, 83, 71, 109, 65, 162,
        31, 45, 67, 216, 183, 123, 164, 118, 196, 23, 73, 236, 127, 12, 111, 246,
        108, 161, 59, 82, 41, 157, 85, 170, 251, 96, 134, 177, 187, 204, 62, 90,
        203, 89, 95, 176, 156, 169, 160, 81, 11, 245, 22, 235, 122, 117, 44, 215,
        79, 174, 213, 233, 230, 231, 173, 232, 116, 214, 244, 234, 168, 80, 88, 175
    ];

    public static bool TryEncode(ReadOnlySpan<byte> utf8Data, Span<byte> matrixBuffer, out QrMatrix matrix)
    {
        matrix = default;
        if (matrixBuffer.Length < RequiredBufferSize)
        {
            return false;
        }

        int version = SelectVersion(utf8Data.Length);
        if (version == -1)
        {
            return false;
        }

        int size = 17 + version * 4;
        int gridLen = size * size;
        Span<byte> modules = matrixBuffer[..gridLen];
        modules.Clear();

        Span<byte> isFunction = stackalloc byte[gridLen];
        isFunction.Clear();

        // 1. Construction du flux de données (Header Mode Byte + Données + Padding)
        int totalCw = TotalCodewords[version];
        int numBlocks = NumBlocksL[version];
        int eccPerBlock = EccPerBlockL[version];
        int dataCwCount = totalCw - numBlocks * eccPerBlock;

        Span<byte> dataCodewords = stackalloc byte[350];
        BuildDataCodewords(utf8Data, version, dataCodewords[..dataCwCount]);

        // 2. Calcul Reed-Solomon et entrelacement des blocs
        Span<byte> finalCodewords = stackalloc byte[350];
        InterleaveWithEcc(dataCodewords[..dataCwCount], numBlocks, eccPerBlock, finalCodewords[..totalCw]);

        // 3. Placement des motifs fonctionnels fixes (Finder, Timing, Alignment, Format)
        DrawFunctionPatterns(version, size, modules, isFunction);

        // 4. Placement des bits de données en zigzag
        DrawCodewords(size, modules, isFunction, finalCodewords[..totalCw]);

        // 5. Sélection du meilleur masque sur la grille en octets (0 décalage de bits)
        int bestMask = 0;
        int lowestPenalty = int.MaxValue;
        Span<byte> maskedGrid = stackalloc byte[gridLen];

        for (int mask = 0; mask < 8; mask++)
        {
            modules.CopyTo(maskedGrid);
            ApplyMask(size, maskedGrid, isFunction, mask);
            DrawFormatBits(size, maskedGrid, mask);

            int penalty = ComputePenaltyScore(size, maskedGrid);
            if (penalty < lowestPenalty)
            {
                lowestPenalty = penalty;
                bestMask = mask;
            }
        }

        // Application unique du masque gagnant
        ApplyMask(size, modules, isFunction, bestMask);
        DrawFormatBits(size, modules, bestMask);

        matrix = new QrMatrix(size, modules);
        return true;
    }

    private static int SelectVersion(int byteLength)
    {
        ReadOnlySpan<short> caps = ByteCapacitiesL;
        for (int v = 1; v <= MaxVersion; v++)
        {
            if (byteLength <= caps[v])
            {
                return v;
            }
        }
        return -1;
    }

    private static void BuildDataCodewords(ReadOnlySpan<byte> data, int version, Span<byte> dest)
    {
        dest.Clear();

        if (version <= 9)
        {
            // Mode Byte (4 bits = 0100) + Length (8 bits) -> chaque octet de données est décalé de 4 bits
            dest[0] = (byte)(0x40 | (data.Length >> 4));
            byte carry = (byte)(data.Length << 4);
            int idx = 1;
            foreach (byte b in data)
            {
                dest[idx++] = (byte)(carry | (b >> 4));
                carry = (byte)(b << 4);
            }
            dest[idx++] = carry;

            bool padToggle = false;
            while (idx < dest.Length)
            {
                dest[idx++] = padToggle ? (byte)0x11 : (byte)0xEC;
                padToggle = !padToggle;
            }
        }
        else
        {
            // Version 10 : Mode Byte (4 bits = 0100) + Length (16 bits) -> décalage de 4 bits également
            dest[0] = (byte)(0x40 | (data.Length >> 12));
            dest[1] = (byte)(data.Length >> 4);
            byte carry = (byte)(data.Length << 4);
            int idx = 2;
            foreach (byte b in data)
            {
                dest[idx++] = (byte)(carry | (b >> 4));
                carry = (byte)(b << 4);
            }
            dest[idx++] = carry;

            bool padToggle = false;
            while (idx < dest.Length)
            {
                dest[idx++] = padToggle ? (byte)0x11 : (byte)0xEC;
                padToggle = !padToggle;
            }
        }
    }

    private static void InterleaveWithEcc(ReadOnlySpan<byte> data, int numBlocks, int eccLen, Span<byte> dest)
    {
        Span<byte> divisor = stackalloc byte[32];
        ComputeReedSolomonDivisor(eccLen, divisor[..eccLen]);

        int shortBlockLen = data.Length / numBlocks;
        int numShortBlocks = numBlocks - (data.Length % numBlocks);

        Span<byte> eccStorage = stackalloc byte[128]; // Max 4 blocs * 30 ECC = 120 octets
        int dataOffset = 0;

        for (int b = 0; b < numBlocks; b++)
        {
            int blockLen = shortBlockLen + (b >= numShortBlocks ? 1 : 0);
            ReadOnlySpan<byte> blockData = data.Slice(dataOffset, blockLen);
            dataOffset += blockLen;

            ComputeReedSolomonRemainder(blockData, divisor[..eccLen], eccStorage.Slice(b * eccLen, eccLen));
        }

        // Entrelacement des octets de données
        int outIdx = 0;
        int maxBlockLen = shortBlockLen + (numShortBlocks < numBlocks ? 1 : 0);
        for (int i = 0; i < maxBlockLen; i++)
        {
            int offset = 0;
            for (int b = 0; b < numBlocks; b++)
            {
                int blockLen = shortBlockLen + (b >= numShortBlocks ? 1 : 0);
                if (i < blockLen)
                {
                    dest[outIdx++] = data[offset + i];
                }
                offset += blockLen;
            }
        }

        // Entrelacement des octets ECC
        for (int i = 0; i < eccLen; i++)
        {
            for (int b = 0; b < numBlocks; b++)
            {
                dest[outIdx++] = eccStorage[b * eccLen + i];
            }
        }
    }

    private static void ComputeReedSolomonDivisor(int degree, Span<byte> result)
    {
        result.Clear();
        result[degree - 1] = 1;
        byte root = 1;

        for (int i = 0; i < degree; i++)
        {
            for (int j = 0; j < degree; j++)
            {
                result[j] = MultiplyGf256(result[j], root);
                if (j + 1 < degree)
                {
                    result[j] ^= result[j + 1];
                }
            }
            root = MultiplyGf256(root, 0x02);
        }
    }

    private static void ComputeReedSolomonRemainder(ReadOnlySpan<byte> data, ReadOnlySpan<byte> divisor, Span<byte> result)
    {
        result.Clear();
        ReadOnlySpan<byte> gfLog = GfLog;
        ReadOnlySpan<byte> gfExp = GfExp;

        foreach (byte b in data)
        {
            byte factor = (byte)(b ^ result[0]);
            result[1..].CopyTo(result);
            result[^1] = 0;

            if (factor != 0)
            {
                int logFactor = gfLog[factor];
                for (int i = 0; i < divisor.Length; i++)
                {
                    byte d = divisor[i];
                    if (d != 0)
                    {
                        result[i] ^= gfExp[logFactor + gfLog[d]];
                    }
                }
            }
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static byte MultiplyGf256(byte x, byte y)
    {
        if (x == 0 || y == 0) return 0;
        return GfExp[GfLog[x] + GfLog[y]];
    }

    private static void DrawFunctionPatterns(int version, int size, Span<byte> modules, Span<byte> isFunction)
    {
        // Timing patterns
        for (int i = 0; i < size; i++)
        {
            byte dark = (byte)((i & 1) == 0 ? 1 : 0);
            SetFunctionModule(size, modules, isFunction, 6, i, dark);
            SetFunctionModule(size, modules, isFunction, i, 6, dark);
        }

        // 3 Finder patterns + séparateurs
        DrawFinderPattern(size, modules, isFunction, 3, 3);
        DrawFinderPattern(size, modules, isFunction, size - 4, 3);
        DrawFinderPattern(size, modules, isFunction, 3, size - 4);

        // Alignment patterns (Versions >= 2)
        if (version >= 2)
        {
            int numAlign = version / 7 + 2;
            int step = (version == 32) ? 26 : (size - 13) / (numAlign - 1) * 2;
            Span<int> alignPos = stackalloc int[8];
            alignPos[0] = 6;
            for (int i = numAlign - 1, pos = size - 7; i >= 1; i--, pos -= step)
            {
                alignPos[i] = pos;
            }

            for (int i = 0; i < numAlign; i++)
            {
                for (int j = 0; j < numAlign; j++)
                {
                    if ((i == 0 && j == 0) || (i == 0 && j == numAlign - 1) || (i == numAlign - 1 && j == 0))
                    {
                        continue;
                    }
                    DrawAlignmentPattern(size, modules, isFunction, alignPos[i], alignPos[j]);
                }
            }
        }

        // Réservation des zones d'information de format
        for (int i = 0; i < 9; i++)
        {
            if (i != 6)
            {
                SetFunctionModule(size, modules, isFunction, 8, i, 0);
                SetFunctionModule(size, modules, isFunction, i, 8, 0);
            }
        }
        for (int i = 0; i < 8; i++)
        {
            SetFunctionModule(size, modules, isFunction, size - 1 - i, 8, 0);
            SetFunctionModule(size, modules, isFunction, 8, size - 1 - i, 0);
        }
        SetFunctionModule(size, modules, isFunction, 8, size - 8, 1); // Dark module

        // Information de version (Versions >= 7)
        if (version >= 7)
        {
            uint vBits = VersionInfo[version - 7];
            for (int i = 0; i < 18; i++)
            {
                byte bit = (byte)((vBits >> i) & 1);
                int a = size - 11 + (i % 3);
                int b = i / 3;
                SetFunctionModule(size, modules, isFunction, a, b, bit);
                SetFunctionModule(size, modules, isFunction, b, a, bit);
            }
        }
    }

    private static void DrawFinderPattern(int size, Span<byte> modules, Span<byte> isFunction, int cx, int cy)
    {
        for (int dy = -4; dy <= 4; dy++)
        {
            for (int dx = -4; dx <= 4; dx++)
            {
                int x = cx + dx;
                int y = cy + dy;
                if ((uint)x < (uint)size && (uint)y < (uint)size)
                {
                    int dist = Math.Max(Math.Abs(dx), Math.Abs(dy));
                    SetFunctionModule(size, modules, isFunction, x, y, (byte)(dist != 2 && dist != 4 ? 1 : 0));
                }
            }
        }
    }

    private static void DrawAlignmentPattern(int size, Span<byte> modules, Span<byte> isFunction, int cx, int cy)
    {
        for (int dy = -2; dy <= 2; dy++)
        {
            for (int dx = -2; dx <= 2; dx++)
            {
                int dist = Math.Max(Math.Abs(dx), Math.Abs(dy));
                SetFunctionModule(size, modules, isFunction, cx + dx, cy + dy, (byte)(dist != 1 ? 1 : 0));
            }
        }
    }

    private static void DrawCodewords(int size, Span<byte> modules, ReadOnlySpan<byte> isFunction, ReadOnlySpan<byte> codewords)
    {
        int bitIndex = 0;
        int totalBits = codewords.Length * 8;
        bool upward = true;

        for (int right = size - 1; right >= 1; right -= 2)
        {
            if (right == 6)
            {
                right = 5; // Sauter la colonne de timing verticale
            }

            for (int vert = 0; vert < size; vert++)
            {
                int y = upward ? size - 1 - vert : vert;
                int rowOffset = y * size;
                for (int j = 0; j < 2; j++)
                {
                    int x = right - j;
                    int idx = rowOffset + x;
                    if (isFunction[idx] == 0)
                    {
                        byte dark = 0;
                        if (bitIndex < totalBits)
                        {
                            dark = (byte)((codewords[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1);
                            bitIndex++;
                        }
                        modules[idx] = dark;
                    }
                }
            }
            upward = !upward;
        }
    }

    private static void ApplyMask(int size, Span<byte> modules, ReadOnlySpan<byte> isFunction, int mask)
    {
        switch (mask)
        {
            case 0:
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    for (int x = y & 1; x < size; x += 2)
                    {
                        int idx = row + x;
                        modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                    }
                }
                break;

            case 1:
                for (int y = 0; y < size; y += 2)
                {
                    int row = y * size;
                    for (int x = 0; x < size; x++)
                    {
                        int idx = row + x;
                        modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                    }
                }
                break;

            case 2:
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    for (int x = 0; x < size; x += 3)
                    {
                        int idx = row + x;
                        modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                    }
                }
                break;

            case 3:
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    int rem = y % 3;
                    int startX = rem == 0 ? 0 : 3 - rem;
                    for (int x = startX; x < size; x += 3)
                    {
                        int idx = row + x;
                        modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                    }
                }
                break;

            case 4:
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    int startX = ((y >> 1) & 1) * 3;
                    for (int x = startX; x < size; x += 6)
                    {
                        int end = Math.Min(x + 3, size);
                        for (int k = x; k < end; k++)
                        {
                            int idx = row + k;
                            modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                        }
                    }
                }
                break;

            case 5:
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    int step;
                    if (y % 3 == 0)
                    {
                        step = (y & 1) == 0 ? 1 : 2;
                    }
                    else
                    {
                        step = (y & 1) == 0 ? 3 : 6;
                    }
                    for (int x = 0; x < size; x += step)
                    {
                        int idx = row + x;
                        modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                    }
                }
                break;

            case 6:
            {
                Span<byte> pat = stackalloc byte[6];
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    int ym6 = y % 6;
                    for (int k = 0; k < 6; k++)
                    {
                        int xy = k * ym6;
                        pat[k] = (byte)((((xy & 1) + (xy % 3)) & 1) == 0 ? 1 : 0);
                    }
                    int x = 0;
                    for (; x + 6 <= size; x += 6)
                    {
                        for (int k = 0; k < 6; k++)
                        {
                            if (pat[k] != 0)
                            {
                                int idx = row + x + k;
                                modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                            }
                        }
                    }
                    for (int k = 0; x + k < size; k++)
                    {
                        if (pat[k] != 0)
                        {
                            int idx = row + x + k;
                            modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                        }
                    }
                }
                break;
            }

            case 7:
            {
                Span<byte> pat = stackalloc byte[6];
                for (int y = 0; y < size; y++)
                {
                    int row = y * size;
                    int ym6 = y % 6;
                    for (int k = 0; k < 6; k++)
                    {
                        pat[k] = (byte)(((((k + ym6) & 1) + ((k * ym6) % 3)) & 1) == 0 ? 1 : 0);
                    }
                    int x = 0;
                    for (; x + 6 <= size; x += 6)
                    {
                        for (int k = 0; k < 6; k++)
                        {
                            if (pat[k] != 0)
                            {
                                int idx = row + x + k;
                                modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                            }
                        }
                    }
                    for (int k = 0; x + k < size; k++)
                    {
                        if (pat[k] != 0)
                        {
                            int idx = row + x + k;
                            modules[idx] ^= (byte)(1 ^ isFunction[idx]);
                        }
                    }
                }
                break;
            }
        }
    }

    private static void DrawFormatBits(int size, Span<byte> modules, int mask)
    {
        ushort data = FormatInfoL[mask];

        for (int i = 0; i <= 5; i++)
        {
            modules[i * size + 8] = (byte)((data >> i) & 1);
        }
        modules[7 * size + 8] = (byte)((data >> 6) & 1);
        modules[8 * size + 8] = (byte)((data >> 7) & 1);
        modules[8 * size + 7] = (byte)((data >> 8) & 1);
        for (int i = 9; i < 15; i++)
        {
            modules[8 * size + (14 - i)] = (byte)((data >> i) & 1);
        }

        for (int i = 0; i < 8; i++)
        {
            modules[8 * size + (size - 1 - i)] = (byte)((data >> i) & 1);
        }
        for (int i = 8; i < 15; i++)
        {
            modules[(size - 15 + i) * size + 8] = (byte)((data >> i) & 1);
        }
    }

    private static int ComputePenaltyScore(int size, ReadOnlySpan<byte> modules)
    {
        int penalty = 0;
        int darkCount = 0;

        Span<byte> colRuns = stackalloc byte[MaxGridSize];
        Span<byte> prevCols = stackalloc byte[MaxGridSize];
        ReadOnlySpan<byte> firstRow = modules[..size];
        firstRow.CopyTo(prevCols);
        colRuns[..size].Fill(1);

        for (int y = 0; y < size; y++)
        {
            ReadOnlySpan<byte> row = modules.Slice(y * size, size);
            bool hasNextRow = y < size - 1;
            ReadOnlySpan<byte> nextRow = hasNextRow ? modules.Slice((y + 1) * size, size) : default;

            int runRow = 1;
            byte prevRow = row[0];
            darkCount += prevRow;

            if (y > 0)
            {
                if (prevRow == prevCols[0])
                {
                    int cr = ++colRuns[0];
                    if (cr == 5) penalty += 3;
                    else if (cr > 5) penalty++;
                }
                else
                {
                    colRuns[0] = 1;
                    prevCols[0] = prevRow;
                }
            }

            if (hasNextRow && prevRow == row[1] && prevRow == nextRow[0] && prevRow == nextRow[1])
            {
                penalty += 3;
            }

            for (int x = 1; x < size; x++)
            {
                byte cur = row[x];
                darkCount += cur;

                // Règle 1 (ligne)
                if (cur == prevRow)
                {
                    runRow++;
                    if (runRow == 5) penalty += 3;
                    else if (runRow > 5) penalty++;
                }
                else
                {
                    runRow = 1;
                    prevRow = cur;
                }

                // Règle 1 (colonne, accès séquentiel sans saut de stride)
                if (y > 0)
                {
                    if (cur == prevCols[x])
                    {
                        int cr = ++colRuns[x];
                        if (cr == 5) penalty += 3;
                        else if (cr > 5) penalty++;
                    }
                    else
                    {
                        colRuns[x] = 1;
                        prevCols[x] = cur;
                    }
                }

                // Règle 2 : Blocs 2x2 de même couleur
                if (hasNextRow && x < size - 1 && cur == row[x + 1] && cur == nextRow[x] && cur == nextRow[x + 1])
                {
                    penalty += 3;
                }
            }
        }

        // Règle 4 : Équilibre clair/foncé autour de 50%
        int totalModules = size * size;
        int k = Math.Abs(darkCount * 20 - totalModules * 10) / totalModules;
        penalty += k * 10;

        return penalty;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void SetFunctionModule(int size, Span<byte> modules, Span<byte> isFunction, int x, int y, byte dark)
    {
        int idx = y * size + x;
        modules[idx] = dark;
        isFunction[idx] = 1;
    }
}
