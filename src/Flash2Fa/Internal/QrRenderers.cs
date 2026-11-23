using System.Buffers;
using System.Buffers.Binary;
using System.Runtime.CompilerServices;

namespace Flash2Fa.Internal;

internal static class QrRenderers
{
    private static ReadOnlySpan<byte> PngSignature => [137, 80, 78, 71, 13, 10, 26, 10];

    private static ReadOnlySpan<uint> Crc32Table =>
    [
        0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA, 0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
        0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988, 0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
        0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE, 0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
        0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC, 0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
        0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172, 0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
        0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940, 0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
        0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116, 0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
        0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924, 0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
        0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A, 0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
        0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818, 0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
        0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E, 0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
        0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C, 0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
        0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2, 0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
        0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0, 0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
        0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086, 0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
        0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4, 0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
        0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A, 0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
        0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8, 0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
        0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE, 0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
        0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC, 0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
        0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252, 0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
        0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60, 0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
        0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236, 0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
        0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04, 0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
        0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A, 0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
        0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38, 0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
        0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E, 0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
        0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C, 0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
        0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2, 0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
        0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0, 0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
        0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6, 0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
        0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94, 0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D
    ];

    public static bool TryRenderSvg(in QrMatrix matrix, QrCodeOptions options, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        var (fg, bg, quietZone, scale) = options.ResolveSafeValues();
        int size = matrix.Size;
        int totalModules = size + quietZone * 2;
        int pixelSize = totalModules * scale;

        if (destination.Length < 256)
        {
            return false;
        }

        int pos = 0;
        WriteBytes("<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 "u8, destination, ref pos);
        WriteInt(totalModules, destination, ref pos);
        destination[pos++] = (byte)' ';
        WriteInt(totalModules, destination, ref pos);
        WriteBytes("\" width=\""u8, destination, ref pos);
        WriteInt(pixelSize, destination, ref pos);
        WriteBytes("\" height=\""u8, destination, ref pos);
        WriteInt(pixelSize, destination, ref pos);
        destination[pos++] = (byte)'"';
        if (options.Shape == QrModuleShape.Square)
        {
            WriteBytes(" shape-rendering=\"crispEdges\""u8, destination, ref pos);
        }
        WriteBytes("><rect width=\"100%\" height=\"100%\" fill=\"#"u8, destination, ref pos);
        WriteHexColor(bg, destination, ref pos);
        WriteBytes("\"/><path fill=\"#"u8, destination, ref pos);
        WriteHexColor(fg, destination, ref pos);
        WriteBytes("\" d=\""u8, destination, ref pos);

        if (options.Shape == QrModuleShape.Square)
        {
            for (int y = 0; y < size; y++)
            {
                ReadOnlySpan<byte> row = matrix.GetRow(y);
                int sy = y + quietZone;
                int x = 0;
                while (x < size)
                {
                    if (row[x] == 0)
                    {
                        x++;
                        continue;
                    }

                    int runStart = x;
                    while (x < size && row[x] != 0)
                    {
                        x++;
                    }

                    if (destination.Length - pos < 24)
                    {
                        return false;
                    }

                    int runLength = x - runStart;
                    destination[pos++] = (byte)'M';
                    WriteSmallInt(runStart + quietZone, destination, ref pos);
                    destination[pos++] = (byte)',';
                    WriteSmallInt(sy, destination, ref pos);
                    destination[pos++] = (byte)'h';
                    WriteSmallInt(runLength, destination, ref pos);
                    WriteBytes("v1h-"u8, destination, ref pos);
                    WriteSmallInt(runLength, destination, ref pos);
                    destination[pos++] = (byte)'z';
                }
            }
        }
        else
        {
            bool isDots = options.Shape == QrModuleShape.Dots;
            ReadOnlySpan<byte> shapeSuffix = isDots
                ? ".1a.4,.4 0 1,1 0,.8a.4,.4 0 1,1 0,-.8"u8
                : "h.6q.2,0 .2,.2v.6q0,.2-.2,.2h-.6q-.2,0-.2-.2v-.6q0-.2.2-.2"u8;

            for (int y = 0; y < size; y++)
            {
                ReadOnlySpan<byte> row = matrix.GetRow(y);
                int sy = y + quietZone;
                bool finderRowTopOrBottom = y < 7 || y >= size - 7;

                for (int x = 0; x < size; x++)
                {
                    if (row[x] == 0)
                    {
                        continue;
                    }

                    if (destination.Length - pos < 72)
                    {
                        return false;
                    }

                    int sx = x + quietZone;
                    bool isFinder = finderRowTopOrBottom && (x < 7 || (x >= size - 7 && y < 7));

                    destination[pos++] = (byte)'M';
                    WriteSmallInt(sx, destination, ref pos);

                    if (isFinder)
                    {
                        destination[pos++] = (byte)',';
                        WriteSmallInt(sy, destination, ref pos);
                        WriteBytes("h1v1h-1z"u8, destination, ref pos);
                    }
                    else if (isDots)
                    {
                        WriteBytes(".5,"u8, destination, ref pos);
                        WriteSmallInt(sy, destination, ref pos);
                        WriteBytes(shapeSuffix, destination, ref pos);
                    }
                    else
                    {
                        WriteBytes(".2,"u8, destination, ref pos);
                        WriteSmallInt(sy, destination, ref pos);
                        WriteBytes(shapeSuffix, destination, ref pos);
                    }
                }
            }
        }

        ReadOnlySpan<byte> footer = "\"/></svg>"u8;
        if (destination.Length - pos < footer.Length)
        {
            return false;
        }

        footer.CopyTo(destination[pos..]);
        bytesWritten = pos + footer.Length;
        return true;
    }

    public static bool TryRenderPng(in QrMatrix matrix, QrCodeOptions options, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        var (fg, bg, quietZone, scale) = options.ResolveSafeValues();
        int size = matrix.Size;
        int totalModules = size + quietZone * 2;
        int imgSize = totalModules * scale;

        int rowDataBytes = (imgSize + 7) >> 3;
        int stride = 1 + rowDataBytes;
        int rawScanlineSize = imgSize * stride;

        // Masques de pixels pré-calculés alignés MSB (bit 31 = pixel dx=0)
        Span<uint> squareRowMasks = stackalloc uint[16];
        Span<uint> customRowMasks = stackalloc uint[16];
        BuildShapeRowMasks(scale, QrModuleShape.Square, squareRowMasks[..scale]);
        BuildShapeRowMasks(scale, options.Shape, customRowMasks[..scale]);

        byte[] rawScanlines = ArrayPool<byte>.Shared.Rent(rawScanlineSize);
        byte[] compressedBuffer = ArrayPool<byte>.Shared.Rent(rawScanlineSize + (rawScanlineSize >> 2) + 128);

        try
        {
            Span<byte> scanlines = rawScanlines.AsSpan(0, rawScanlineSize);
            scanlines.Fill(0xFF); // Index 1 = Background

            for (int modY = 0; modY < totalModules; modY++)
            {
                int qrY = modY - quietZone;
                bool isRowInMatrix = (uint)qrY < (uint)size;
                int baseRowOffset = modY * scale * stride;

                for (int sy = 0; sy < scale; sy++)
                {
                    scanlines[baseRowOffset + sy * stride] = 0x00;
                }

                if (!isRowInMatrix)
                {
                    continue;
                }

                ReadOnlySpan<byte> row = matrix.GetRow(qrY);
                bool finderRowTopOrBottom = qrY < 7 || qrY >= size - 7;

                for (int modX = 0; modX < size; modX++)
                {
                    if (row[modX] == 0)
                    {
                        continue;
                    }

                    int startPxX = (modX + quietZone) * scale;
                    bool isFinder = finderRowTopOrBottom && (modX < 7 || (modX >= size - 7 && qrY < 7));
                    ReadOnlySpan<uint> activeMasks = isFinder ? squareRowMasks[..scale] : customRowMasks[..scale];

                    DrawModuleWithMask(scanlines, baseRowOffset, stride, startPxX, scale, activeMasks);
                }
            }

            // Compression Zlib Fixed-Huffman 100% managée (0 allocation, 0 P/Invoke)
            int compressedLength = CompressZlibQrScanlines(scanlines, stride, scale, compressedBuffer);

            int totalPngLength = 8 + 25 + 18 + (12 + compressedLength) + 12;
            if (destination.Length < totalPngLength)
            {
                return false;
            }

            int pos = 0;
            PngSignature.CopyTo(destination);
            pos += 8;

            Span<byte> ihdrData = stackalloc byte[13];
            BinaryPrimitives.WriteInt32BigEndian(ihdrData[0..4], imgSize);
            BinaryPrimitives.WriteInt32BigEndian(ihdrData[4..8], imgSize);
            ihdrData[8] = 1; // 1-bit
            ihdrData[9] = 3; // Indexed-color
            ihdrData[10] = 0;
            ihdrData[11] = 0;
            ihdrData[12] = 0;
            pos += WritePngChunk(destination[pos..], "IHDR"u8, ihdrData);

            Span<byte> plteData = [fg.R, fg.G, fg.B, bg.R, bg.G, bg.B];
            pos += WritePngChunk(destination[pos..], "PLTE"u8, plteData);

            pos += WritePngChunk(destination[pos..], "IDAT"u8, compressedBuffer.AsSpan(0, compressedLength));
            pos += WritePngChunk(destination[pos..], "IEND"u8, []);

            bytesWritten = pos;
            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rawScanlines);
            ArrayPool<byte>.Shared.Return(compressedBuffer);
        }
    }

    private static void BuildShapeRowMasks(int scale, QrModuleShape shape, Span<uint> rowMasks)
    {
        double center = (scale - 1) / 2.0;
        double maxRadiusSq = (scale * 0.45) * (scale * 0.45);

        for (int dy = 0; dy < scale; dy++)
        {
            uint mask = 0;
            for (int dx = 0; dx < scale; dx++)
            {
                bool draw = shape switch
                {
                    QrModuleShape.Square => true,
                    QrModuleShape.Rounded => !((dx == 0 || dx == scale - 1) && (dy == 0 || dy == scale - 1)),
                    QrModuleShape.Dots => ((dx - center) * (dx - center) + (dy - center) * (dy - center)) <= maxRadiusSq,
                    _ => true
                };

                if (draw)
                {
                    mask |= 1u << (31 - dx);
                }
            }
            rowMasks[dy] = mask;
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void DrawModuleWithMask(
        Span<byte> scanlines,
        int baseRowOffset,
        int stride,
        int startPxX,
        int scale,
        ReadOnlySpan<uint> rowMasks)
    {
        int byteIdx = startPxX >> 3;
        int bitOffset = startPxX & 7;
        int totalBits = scale + bitOffset;
        int colBase = 1 + byteIdx;

        if (totalBits <= 8)
        {
            for (int dy = 0; dy < scale; dy++)
            {
                uint shifted = rowMasks[dy] >> bitOffset;
                scanlines[baseRowOffset + dy * stride + colBase] &= (byte)~(shifted >> 24);
            }
        }
        else if (totalBits <= 16)
        {
            for (int dy = 0; dy < scale; dy++)
            {
                uint shifted = rowMasks[dy] >> bitOffset;
                int offset = baseRowOffset + dy * stride + colBase;
                scanlines[offset] &= (byte)~(shifted >> 24);
                scanlines[offset + 1] &= (byte)~(shifted >> 16);
            }
        }
        else
        {
            for (int dy = 0; dy < scale; dy++)
            {
                uint shifted = rowMasks[dy] >> bitOffset;
                int offset = baseRowOffset + dy * stride + colBase;
                scanlines[offset] &= (byte)~(shifted >> 24);
                scanlines[offset + 1] &= (byte)~(shifted >> 16);
                scanlines[offset + 2] &= (byte)~(shifted >> 8);
            }
        }
    }

    private static int CompressZlibQrScanlines(ReadOnlySpan<byte> scanlines, int stride, int scale, Span<byte> dest)
    {
        // En-tête Zlib : CMF=0x78 (Deflate 32K), FLG=0x01 (Fastest, FCHECK valide)
        dest[0] = 0x78;
        dest[1] = 0x01;
        int pos = 2;

        uint bitBuf = 0b011; // BFINAL=1 (1 bit) + BTYPE=01 Fixed Huffman (2 bits)
        int bitCount = 3;

        int totalScanlines = scanlines.Length / stride;
        int modY = 0;

        while (modY < totalScanlines)
        {
            int blockRows = Math.Min(scale, totalScanlines - modY);
            ReadOnlySpan<byte> firstRow = scanlines.Slice(modY * stride, stride);

            // 1. Encodage de la première ligne du module avec RLE simple (distance = 1)
            int x = 0;
            while (x < stride)
            {
                byte b = firstRow[x];
                WriteFixedLiteral(b, dest, ref pos, ref bitBuf, ref bitCount);
                x++;

                int run = 0;
                while (x + run < stride && firstRow[x + run] == b && run < 258)
                {
                    run++;
                }

                if (run >= 3)
                {
                    WriteFixedMatch(run, 1, dest, ref pos, ref bitBuf, ref bitCount);
                    x += run;
                }
            }

            // 2. Les (blockRows - 1) lignes suivantes sont identiques ou très similaires :
            //    vérification rapide si identiques à la première ligne (toujours vrai pour Square et QuietZone)
            int identicalRows = 0;
            for (int sy = 1; sy < blockRows; sy++)
            {
                ReadOnlySpan<byte> nextRow = scanlines.Slice((modY + sy) * stride, stride);
                if (firstRow.SequenceEqual(nextRow))
                {
                    identicalRows++;
                }
                else
                {
                    break;
                }
            }

            if (identicalRows > 0)
            {
                int remainingCopy = identicalRows * stride;
                while (remainingCopy >= 3)
                {
                    int len = Math.Min(258, remainingCopy);
                    WriteFixedMatch(len, stride, dest, ref pos, ref bitBuf, ref bitCount);
                    remainingCopy -= len;
                }
                for (int r = identicalRows * stride - remainingCopy; r < identicalRows * stride; r++)
                {
                    WriteFixedLiteral(firstRow[r % stride], dest, ref pos, ref bitBuf, ref bitCount);
                }
            }

            // Lignes restantes si forme non-carrée (Rounded / Dots)
            for (int sy = 1 + identicalRows; sy < blockRows; sy++)
            {
                ReadOnlySpan<byte> row = scanlines.Slice((modY + sy) * stride, stride);
                int rx = 0;
                while (rx < stride)
                {
                    byte b = row[rx];
                    WriteFixedLiteral(b, dest, ref pos, ref bitBuf, ref bitCount);
                    rx++;

                    int run = 0;
                    while (rx + run < stride && row[rx + run] == b && run < 258)
                    {
                        run++;
                    }

                    if (run >= 3)
                    {
                        WriteFixedMatch(run, 1, dest, ref pos, ref bitBuf, ref bitCount);
                        rx += run;
                    }
                }
            }

            modY += blockRows;
        }

        // Symbole End-Of-Block (256 = 7 bits à 0)
        WriteBits(0, 7, dest, ref pos, ref bitBuf, ref bitCount);
        if (bitCount > 0)
        {
            dest[pos++] = (byte)bitBuf;
        }

        // Checksum Adler-32
        uint adler = ComputeAdler32(scanlines);
        BinaryPrimitives.WriteUInt32BigEndian(dest[pos..], adler);
        return pos + 4;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteFixedLiteral(byte literal, Span<byte> dest, ref int pos, ref uint bitBuf, ref int bitCount)
    {
        if (literal <= 143)
        {
            uint code = ReverseBits((uint)(0x30 + literal), 8);
            WriteBits(code, 8, dest, ref pos, ref bitBuf, ref bitCount);
        }
        else
        {
            uint code = ReverseBits((uint)(0x190 + literal - 144), 9);
            WriteBits(code, 9, dest, ref pos, ref bitBuf, ref bitCount);
        }
    }

    private static void WriteFixedMatch(int length, int distance, Span<byte> dest, ref int pos, ref uint bitBuf, ref int bitCount)
    {
        // Encodage longueur (3..258)
        int lenSym;
        int lenExtraBits = 0;
        int lenExtraVal = 0;

        if (length <= 10)
        {
            lenSym = 254 + length;
        }
        else if (length == 258)
        {
            lenSym = 285;
        }
        else
        {
            int n = length - 3;
            int log = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)n);
            lenExtraBits = log - 2;
            int baseSym = 261 + lenExtraBits * 4;
            int step = 1 << lenExtraBits;
            int baseLen = 3 + (4 << lenExtraBits);
            int sub = (length - baseLen) >> lenExtraBits;
            lenSym = baseSym + sub;
            lenExtraVal = (length - baseLen) & (step - 1);
        }

        if (lenSym <= 279)
        {
            uint code = ReverseBits((uint)(lenSym - 256), 7);
            WriteBits(code, 7, dest, ref pos, ref bitBuf, ref bitCount);
        }
        else
        {
            uint code = ReverseBits((uint)(0xC0 + lenSym - 280), 8);
            WriteBits(code, 8, dest, ref pos, ref bitBuf, ref bitCount);
        }

        if (lenExtraBits > 0)
        {
            WriteBits((uint)lenExtraVal, lenExtraBits, dest, ref pos, ref bitBuf, ref bitCount);
        }

        // Encodage distance (1..32768)
        int distSym;
        int distExtraBits = 0;
        int distExtraVal = 0;

        if (distance <= 4)
        {
            distSym = distance - 1;
        }
        else
        {
            int d = distance - 1;
            int log = 31 - System.Numerics.BitOperations.LeadingZeroCount((uint)d);
            distExtraBits = log - 1;
            distSym = 2 + distExtraBits * 2 + ((d >> distExtraBits) & 1);
            distExtraVal = d & ((1 << distExtraBits) - 1);
        }

        uint distCode = ReverseBits((uint)distSym, 5);
        WriteBits(distCode, 5, dest, ref pos, ref bitBuf, ref bitCount);

        if (distExtraBits > 0)
        {
            WriteBits((uint)distExtraVal, distExtraBits, dest, ref pos, ref bitBuf, ref bitCount);
        }
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static uint ReverseBits(uint value, int bitCount)
    {
        uint rev = 0;
        for (int i = 0; i < bitCount; i++)
        {
            rev = (rev << 1) | (value & 1);
            value >>= 1;
        }
        return rev;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteBits(uint bits, int count, Span<byte> dest, ref int pos, ref uint bitBuf, ref int bitCount)
    {
        bitBuf |= bits << bitCount;
        bitCount += count;
        while (bitCount >= 8)
        {
            dest[pos++] = (byte)bitBuf;
            bitBuf >>= 8;
            bitCount -= 8;
        }
    }

    private static uint ComputeAdler32(ReadOnlySpan<byte> data)
    {
        const uint mod = 65521;
        uint s1 = 1;
        uint s2 = 0;

        int i = 0;
        while (i < data.Length)
        {
            int chunkEnd = Math.Min(i + 5552, data.Length);
            while (i + 4 <= chunkEnd)
            {
                s1 += data[i]; s2 += s1;
                s1 += data[i + 1]; s2 += s1;
                s1 += data[i + 2]; s2 += s1;
                s1 += data[i + 3]; s2 += s1;
                i += 4;
            }
            while (i < chunkEnd)
            {
                s1 += data[i++];
                s2 += s1;
            }
            s1 %= mod;
            s2 %= mod;
        }

        return (s2 << 16) | s1;
    }

    private static int WritePngChunk(Span<byte> dest, ReadOnlySpan<byte> chunkType, ReadOnlySpan<byte> data)
    {
        BinaryPrimitives.WriteInt32BigEndian(dest[0..4], data.Length);
        chunkType.CopyTo(dest[4..8]);
        data.CopyTo(dest[8..]);

        uint crc = ComputeCrc32(dest.Slice(4, 4 + data.Length));
        BinaryPrimitives.WriteUInt32BigEndian(dest.Slice(8 + data.Length, 4), crc);

        return 12 + data.Length;
    }

    private static uint ComputeCrc32(ReadOnlySpan<byte> data)
    {
        uint crc = 0xFFFFFFFF;
        ReadOnlySpan<uint> table = Crc32Table;
        foreach (byte b in data)
        {
            crc = table[(int)((crc ^ b) & 0xFF)] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFF;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteBytes(ReadOnlySpan<byte> src, Span<byte> dest, ref int pos)
    {
        src.CopyTo(dest[pos..]);
        pos += src.Length;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteSmallInt(int value, Span<byte> dest, ref int pos)
    {
        if (value < 10)
        {
            dest[pos++] = (byte)('0' + value);
        }
        else if (value < 100)
        {
            int tens = value / 10;
            dest[pos++] = (byte)('0' + tens);
            dest[pos++] = (byte)('0' + (value - tens * 10));
        }
        else
        {
            WriteInt(value, dest, ref pos);
        }
    }

    private static void WriteInt(int value, Span<byte> dest, ref int pos)
    {
        value.TryFormat(dest[pos..], out int written);
        pos += written;
    }

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private static void WriteHexColor(QrColor c, Span<byte> dest, ref int pos)
    {
        ReadOnlySpan<byte> hex = "0123456789abcdef"u8;
        dest[pos++] = hex[c.R >> 4];
        dest[pos++] = hex[c.R & 0x0F];
        dest[pos++] = hex[c.G >> 4];
        dest[pos++] = hex[c.G & 0x0F];
        dest[pos++] = hex[c.B >> 4];
        dest[pos++] = hex[c.B & 0x0F];
    }
}
