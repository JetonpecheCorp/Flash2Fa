using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Flash2Fa;

BenchmarkRunner.Run<Flash2FaBenchmarkSuite>();

[MemoryDiagnoser]
[RankColumn]
public class Flash2FaBenchmarkSuite
{
    private const string Secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
    private const string Issuer = "FlashApp";
    private const string Account = "alice@example.com";

    private string _validCode = string.Empty;
    private RecoveryCodes _recoveryCodes;
    private byte[] _renderBuffer = null!;
    private char[] _codeBuffer = null!;
    private QrCodeOptions _customDotsOptions;

    [GlobalSetup]
    public void Setup()
    {
        Flash2FaService.TryGenerateCode(Secret, out _validCode);
        _recoveryCodes = Flash2FaService.GenerateRecoveryCodes();
        _renderBuffer = new byte[64 * 1024];
        _codeBuffer = new char[8];

        QrColor.TryFromHex("#38BDF8", out QrColor fg);
        QrColor.TryFromHex("#0F172A", out QrColor bg);
        _customDotsOptions = new QrCodeOptions(
            Size: QrCodeSize.Medium,
            Foreground: fg,
            Background: bg,
            Shape: QrModuleShape.Dots,
            QuietZone: 2);
    }

    [Benchmark(Description = "TOTP: VerifyCode (Hot Path)")]
    public bool VerifyTotpCode()
    {
        return Flash2FaService.VerifyCode(Secret, _validCode, out _);
    }

    [Benchmark(Description = "TOTP: TryGenerateCode (Span)")]
    public bool GenerateTotpCode_ZeroAlloc()
    {
        return Flash2FaService.TryGenerateCode(Secret, _codeBuffer, out _, out _);
    }

    [Benchmark(Description = "Recovery: VerifyCode (8 hashes)")]
    public int VerifyRecoveryCode_ListOf8()
    {
        return Flash2FaService.VerifyRecoveryCode(_recoveryCodes.PlainCodes[4], _recoveryCodes.HashedCodes);
    }

    [Benchmark(Description = "QR Code: PNG 1-bit (Span)")]
    public bool RenderQrCode_Png_ZeroAlloc()
    {
        return Flash2FaService.TryGenerateQrCodeBytes(
            Secret, Issuer, Account, _renderBuffer, out _, out _, QrImageFormat.Png);
    }

    [Benchmark(Description = "QR Code: SVG Custom Dots (Span)")]
    public bool RenderQrCode_Svg_Dots_ZeroAlloc()
    {
        return Flash2FaService.TryGenerateQrCodeBytes(
            Secret, Issuer, Account, _renderBuffer, out _, out _, QrImageFormat.Svg, _customDotsOptions);
    }

    [Benchmark(Description = "Setup: CreateSetup Complet (PNG + 8 Recovery)")]
    public bool CreateFullSetup_Png()
    {
        return Flash2FaService.TryCreateSetup(Issuer, Account, out _, out _, QrImageFormat.Png);
    }
}