using System.Buffers.Binary;
using System.Text;

namespace Flash2Fa.Tests;

public class Flash2FaTests
{
    private const string RfcSecretSha1 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    private const string RfcSecretSha256 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA";
    private const string RfcSecretSha512 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNB";

    [Theory]
    [InlineData(59L, TotpAlgorithm.Sha1, RfcSecretSha1, "94287082")]
    [InlineData(59L, TotpAlgorithm.Sha256, RfcSecretSha256, "46119246")]
    [InlineData(59L, TotpAlgorithm.Sha512, RfcSecretSha512, "90693936")]
    [InlineData(1111111109L, TotpAlgorithm.Sha1, RfcSecretSha1, "07081804")]
    [InlineData(1111111109L, TotpAlgorithm.Sha256, RfcSecretSha256, "68084774")]
    [InlineData(1111111109L, TotpAlgorithm.Sha512, RfcSecretSha512, "25091201")]
    [InlineData(1234567890L, TotpAlgorithm.Sha1, RfcSecretSha1, "89005924")]
    [InlineData(2000000000L, TotpAlgorithm.Sha1, RfcSecretSha1, "69279037")]
    public void TryGenerateCode_MatchesOfficialRfc6238TestVectors(
        long unixSeconds,
        TotpAlgorithm algorithm,
        string secret,
        string expectedCode)
    {
        DateTimeOffset timestamp = DateTimeOffset.FromUnixTimeSeconds(unixSeconds);

        bool success = Flash2FaService.TryGenerateCode(
            secret,
            out string code,
            out int remainingSeconds,
            timestamp: timestamp,
            algorithm: algorithm,
            digits: TotpDigits.Eight);

        Assert.True(success);
        Assert.Equal(expectedCode, code);
        Assert.InRange(remainingSeconds, 1, 30);
    }

    [Fact]
    public void TryCreateSetup_GeneratesValidSecretQrAndRecoveryCodes()
    {
        bool created = Flash2FaService.TryCreateSetup(
            "FlashApp",
            "alice@example.com",
            out TwoFactorSetup setup,
            out Flash2FaError error);

        Assert.True(created);
        Assert.Equal(Flash2FaError.None, error);
        Assert.Equal(32, setup.Secret.Length);
        Assert.True(Flash2FaService.IsValidSecret(setup.Secret));
        Assert.StartsWith("data:image/png;base64,", setup.QrCodeBase64);
        Assert.Equal(8, setup.RecoveryCodes.PlainCodes.Length);
        Assert.Equal(8, setup.RecoveryCodes.HashedCodes.Length);

        Assert.True(Flash2FaService.TryGenerateCode(setup.Secret, out string liveCode));
        Assert.Equal(6, liveCode.Length);
        Assert.True(Flash2FaService.VerifyCode(setup.Secret, liveCode, out long matchedStep));
        Assert.True(matchedStep > 0);
    }

    [Fact]
    public void RecoveryCodes_VerificationIsCaseAndFormatInsensitive()
    {
        Assert.True(Flash2FaService.TryGenerateRecoveryCodes(5, out RecoveryCodes codes));
        string targetPlain = codes.PlainCodes[2];
        string targetHash = codes.HashedCodes[2];

        string messyInput = $"  {targetPlain.Replace("-", " ").ToLowerInvariant()}  ";

        Assert.True(Flash2FaService.VerifyRecoveryCode(messyInput, targetHash));
        Assert.Equal(2, Flash2FaService.VerifyRecoveryCode(messyInput, codes.HashedCodes));
        Assert.Equal(-1, Flash2FaService.VerifyRecoveryCode("INVALID-CODE", codes.HashedCodes));
    }

    [Fact]
    public void TryGenerateQrCodeBytes_Png_ProducesValidPngStructure()
    {
        bool ok = Flash2FaService.TryGenerateQrCodeBytes(
            RfcSecretSha1,
            "MonService",
            "user@test.fr",
            out byte[] png,
            out Flash2FaError error,
            QrImageFormat.Png,
            new QrCodeOptions(Size: QrCodeSize.Medium));

        Assert.True(ok);
        Assert.Equal(Flash2FaError.None, error);

        byte[] expectedSig = [137, 80, 78, 71, 13, 10, 26, 10];
        Assert.Equal(expectedSig, png[..8]);

        Assert.Equal("IHDR", Encoding.ASCII.GetString(png, 12, 4));
        int width = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16, 4));
        int height = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20, 4));
        Assert.Equal(width, height);
        Assert.True(width >= 200);

        Assert.Equal("IEND", Encoding.ASCII.GetString(png, png.Length - 8, 4));

        // Vérification de la validité du flux Zlib IDAT (décompression + Adler-32)
        int idatIndex = Encoding.ASCII.GetString(png).IndexOf("IDAT", StringComparison.Ordinal);
        Assert.True(idatIndex > 0);
        int idatLen = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(idatIndex - 4, 4));
        using var ms = new MemoryStream(png, idatIndex + 4, idatLen);
        using var zlib = new System.IO.Compression.ZLibStream(ms, System.IO.Compression.CompressionMode.Decompress);
        using var outMs = new MemoryStream();
        zlib.CopyTo(outMs);
        int expectedScanlineBytes = width * (1 + ((width + 7) >> 3));
        Assert.Equal(expectedScanlineBytes, outMs.Length);
    }

    [Fact]
    public void TryGenerateQrCodeBytes_Svg_ProducesValidSvgMarkup()
    {
        bool ok = Flash2FaService.TryGenerateQrCodeBytes(
            RfcSecretSha1,
            "MonService",
            "user@test.fr",
            out byte[] svgBytes,
            out Flash2FaError error,
            QrImageFormat.Svg,
            new QrCodeOptions(Size: QrCodeSize.Large));

        Assert.True(ok);
        Assert.Equal(Flash2FaError.None, error);

        string svg = Encoding.UTF8.GetString(svgBytes);
        Assert.StartsWith("<svg xmlns=\"http://www.w3.org/2000/svg\"", svg);
        Assert.Contains("<path fill=\"#000000\" d=\"M", svg);
        Assert.EndsWith("</svg>", svg);
    }

    [Fact]
    public void CustomQrCodeOptions_EnforcesReadableContrastAutomatically()
    {
        Assert.True(QrColor.TryFromHex("#F1F5F9", out QrColor unreadableLightGray));

        var unreadableOptions = new QrCodeOptions(
            Size: QrCodeSize.Small,
            Foreground: unreadableLightGray,
            Background: QrColor.White,
            Shape: QrModuleShape.Dots,
            QuietZone: 2,
            EnforceReadableContrast: true);

        bool ok = Flash2FaService.TryGenerateQrCodeBytes(
            RfcSecretSha1,
            "MonService",
            "user@test.fr",
            out byte[] svgBytes,
            out Flash2FaError error,
            QrImageFormat.Svg,
            unreadableOptions);

        Assert.True(ok);
        Assert.Equal(Flash2FaError.None, error);

        string svg = Encoding.UTF8.GetString(svgBytes);
        Assert.Contains("fill=\"#ffffff\"", svg);
        Assert.Contains("<path fill=\"#000000\" d=\"M", svg);
    }

    [Fact]
    public void CustomQrCodeOptions_PngIndexedPalette_AppliesCustomColors()
    {
        Assert.True(QrColor.TryFromHex("#38BDF8", out QrColor skyBlue));
        Assert.True(QrColor.TryFromHex("#0F172A", out QrColor slateDark));

        var darkTheme = new QrCodeOptions(
            Size: QrCodeSize.Medium,
            Foreground: skyBlue,
            Background: slateDark,
            Shape: QrModuleShape.Rounded);

        bool ok = Flash2FaService.TryGenerateQrCodeBytes(
            RfcSecretSha1,
            "MonService",
            "user@test.fr",
            out byte[] png,
            out Flash2FaError error,
            QrImageFormat.Png,
            darkTheme);

        Assert.True(ok);
        Assert.Equal(Flash2FaError.None, error);

        string pngAscii = Encoding.ASCII.GetString(png);
        int plteIndex = pngAscii.IndexOf("PLTE", StringComparison.Ordinal);
        Assert.True(plteIndex > 0);

        Assert.Equal(0x38, png[plteIndex + 4]);
        Assert.Equal(0xBD, png[plteIndex + 5]);
        Assert.Equal(0xF8, png[plteIndex + 6]);
        Assert.Equal(0x0F, png[plteIndex + 7]);
        Assert.Equal(0x17, png[plteIndex + 8]);
        Assert.Equal(0x2A, png[plteIndex + 9]);
    }

    [Fact]
    public void InvalidInputs_ReturnFalseWithSpecificError_WithoutThrowing()
    {
        Assert.False(Flash2FaService.IsValidSecret(""));
        Assert.False(Flash2FaService.IsValidSecret("1089!@#"));
        Assert.False(Flash2FaService.IsValidSecret("ABCD"));
        Assert.True(Flash2FaService.IsValidSecret(RfcSecretSha1));

        // Clé secrète invalide
        Assert.False(Flash2FaService.TryGenerateCode("INVALID_SECRET", out string emptyCode));
        Assert.Equal(string.Empty, emptyCode);

        Assert.False(Flash2FaService.TryGenerateQrCodeBytes("BAD", "App", "user", out _, out Flash2FaError secretErr));
        Assert.Equal(Flash2FaError.InvalidSecret, secretErr);

        // Compte ou émetteur vide
        Assert.False(Flash2FaService.TryCreateSetup("", "user", out _, out Flash2FaError accountErr));
        Assert.Equal(Flash2FaError.InvalidAccountInfo, accountErr);

        // Nombre de codes de secours hors bornes
        Assert.False(Flash2FaService.TryCreateSetup("App", "user", out _, out Flash2FaError countErr, recoveryCodeCount: 0));
        Assert.Equal(Flash2FaError.InvalidRecoveryCodeCount, countErr);

        // Buffer trop petit
        Span<byte> tinyBuffer = stackalloc byte[10];
        Assert.False(Flash2FaService.TryGenerateQrCodeBytes(RfcSecretSha1, "App", "user", tinyBuffer, out _, out Flash2FaError bufErr));
        Assert.Equal(Flash2FaError.BufferTooSmall, bufErr);

        // Couleur hexadécimale invalide
        Assert.False(QrColor.TryFromHex("ZZZZZZ", out _));
        Assert.False(QrColor.TryFromHex("#123", out _));
    }
}