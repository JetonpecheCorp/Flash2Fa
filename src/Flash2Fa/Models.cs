namespace Flash2Fa;

/// <summary>
/// Résultat complet d'une initialisation 2FA pour un nouvel utilisateur.
/// </summary>
/// <param name="Secret">Clé secrète encodée en Base32 à chiffrer et stocker en base.</param>
/// <param name="QrCodeBase64">Image QR Code encodée en Base64 prête à être affichée.</param>
/// <param name="RecoveryCodes">Jeu de codes de secours en clair et hachés.</param>
public readonly record struct TwoFactorSetup(
    string Secret,
    string QrCodeBase64,
    RecoveryCodes RecoveryCodes
);

/// <summary>
/// Paire contenant les codes de récupération lisibles et leurs empreintes SHA-256.
/// </summary>
/// <param name="PlainCodes">Codes en clair à afficher une seule fois à l'utilisateur.</param>
/// <param name="HashedCodes">Empreintes SHA-256 à sauvegarder en base de données.</param>
public readonly record struct RecoveryCodes(
    string[] PlainCodes,
    string[] HashedCodes
);

/// <summary>
/// Représente une couleur RVB 24 bits pour le rendu du QR Code.
/// </summary>
/// <param name="R">Composante rouge (0 à 255).</param>
/// <param name="G">Composante verte (0 à 255).</param>
/// <param name="B">Composante bleue (0 à 255).</param>
public readonly record struct QrColor(byte R, byte G, byte B)
{
    /// <summary>Noir pur (#000000).</summary>
    public static QrColor Black => new(0, 0, 0);

    /// <summary>Blanc pur (#FFFFFF).</summary>
    public static QrColor White => new(255, 255, 255);

    /// <summary>
    /// Tente de convertir une chaîne hexadécimale ("#1E293B" ou "1E293B") en couleur RVB sans lever d'exception.
    /// </summary>
    /// <param name="hex">Chaîne hexadécimale de 6 caractères (avec ou sans préfixe <c>#</c>).</param>
    /// <param name="color">En cas de succès, la couleur <see cref="QrColor"/> correspondante ; sinon la valeur par défaut.</param>
    /// <returns><see langword="true"/> si la chaîne hexadécimale est valide ; sinon <see langword="false"/>.</returns>
    public static bool TryFromHex(ReadOnlySpan<char> hex, out QrColor color)
    {
        color = default;
        if (hex.StartsWith("#"))
        {
            hex = hex[1..];
        }

        if (hex.Length != 6)
        {
            return false;
        }

        Span<byte> rgb = stackalloc byte[3];
        if (Convert.FromHexString(hex, rgb, out _, out int written) != System.Buffers.OperationStatus.Done || written != 3)
        {
            return false;
        }

        color = new QrColor(rgb[0], rgb[1], rgb[2]);
        return true;
    }

    /// <summary>
    /// Convertit une chaîne hexadécimale en couleur RVB, ou retourne <paramref name="fallback"/> si le format est invalide.
    /// </summary>
    /// <param name="hex">Chaîne hexadécimale de 6 caractères (avec ou sans préfixe <c>#</c>).</param>
    /// <param name="fallback">Couleur de repli retournée si <paramref name="hex"/> n'est pas valide.</param>
    /// <returns>La couleur convertie, ou <paramref name="fallback"/> en cas d'échec.</returns>
    public static QrColor FromHexOrDefault(ReadOnlySpan<char> hex, QrColor fallback)
        => TryFromHex(hex, out QrColor color) ? color : fallback;

    internal double GetRelativeLuminance()
    {
        static double Channel(byte c)
        {
            if (c == 0) return 0.0;
            if (c == 255) return 1.0;
            double s = c / 255.0;
            return s <= 0.03928 ? s / 12.92 : Math.Pow((s + 0.055) / 1.055, 2.4);
        }

        return 0.2126 * Channel(R) + 0.7152 * Channel(G) + 0.0722 * Channel(B);
    }
}

/// <summary>
/// Options de personnalisation visuelle du QR Code avec sécurité automatique de scannabilité.
/// </summary>
/// <param name="Size">Taille prédéfinie du QR Code (nombre de pixels par module). <see cref="QrCodeSize.Medium"/> par défaut.</param>
/// <param name="Foreground">Couleur des modules foncés du QR Code. Si <see langword="null"/>, utilise <see cref="QrColor.Black"/>.</param>
/// <param name="Background">Couleur d'arrière-plan du QR Code. Si <see langword="null"/>, utilise <see cref="QrColor.White"/>.</param>
/// <param name="Shape">Forme géométrique des modules de données (<see cref="QrModuleShape.Square"/> par défaut).</param>
/// <param name="QuietZone">Marge de sécurité autour du QR Code en nombre de modules (bornée entre 0 et 10, 4 par défaut).</param>
/// <param name="EnforceReadableContrast">Indique s'il faut corriger automatiquement la couleur de premier plan lorsque le contraste avec le fond est inférieur à 3,0:1 (<see langword="true"/> par défaut).</param>
public readonly record struct QrCodeOptions(
    QrCodeSize Size = QrCodeSize.Medium,
    QrColor? Foreground = null,
    QrColor? Background = null,
    QrModuleShape Shape = QrModuleShape.Square,
    int QuietZone = 4,
    bool EnforceReadableContrast = true)
{
    /// <summary>Initialise les options standard par défaut (Noir sur Blanc, carrés, taille moyenne, marge de 4 modules).</summary>
    public QrCodeOptions()
        : this(QrCodeSize.Medium, null, null, QrModuleShape.Square, 4, true)
    {
    }

    /// <summary>Options standard par défaut (Noir sur Blanc, carrés, taille moyenne).</summary>
    public static QrCodeOptions Default => new();

    internal (QrColor EffectiveFg, QrColor EffectiveBg, int EffectiveQuietZone, int EffectiveScale) ResolveSafeValues()
    {
        QrColor bg = Background ?? QrColor.White;
        QrColor fg = Foreground ?? QrColor.Black;
        int quiet = Math.Clamp(QuietZone, 0, 10);
        int scale = Size is QrCodeSize.Small or QrCodeSize.Medium or QrCodeSize.Large
            ? (int)Size
            : (int)QrCodeSize.Medium;

        if (EnforceReadableContrast)
        {
            double lumFg = fg.GetRelativeLuminance();
            double lumBg = bg.GetRelativeLuminance();
            double lighter = Math.Max(lumFg, lumBg);
            double darker = Math.Min(lumFg, lumBg);
            double contrastRatio = (lighter + 0.05) / (darker + 0.05);

            // Seuil minimal de 3.0:1 pour garantir la lecture par les capteurs photo
            if (contrastRatio < 3.0)
            {
                fg = lumBg > 0.5 ? QrColor.Black : QrColor.White;
            }
        }

        return (fg, bg, quiet, scale);
    }
}