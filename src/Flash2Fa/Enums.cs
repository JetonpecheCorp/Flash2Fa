namespace Flash2Fa;

/// <summary>
/// Forme géométrique des modules composant le QR Code.
/// </summary>
public enum QrModuleShape
{
    /// <summary>Modules carrés classiques (net et universel).</summary>
    Square,

    /// <summary>Modules carrés aux angles légèrement adoucis.</summary>
    Rounded,

    /// <summary>Modules circulaires modernes.</summary>
    Dots
}

/// <summary>
/// Format d'image généré pour le QR Code.
/// </summary>
public enum QrImageFormat
{
    /// <summary>Image matricielle PNG 1-bit (compatibilité universelle).</summary>
    Png,

    /// <summary>Image vectorielle SVG (poids minimal, netteté infinie).</summary>
    Svg
}

/// <summary>
/// Taille prédéfinie du QR Code garantissant une lisibilité optimale.
/// La valeur entière correspond au nombre de pixels par module.
/// </summary>
public enum QrCodeSize
{
    /// <summary>Format compact (~130x130 px), idéal pour mobile ou email.</summary>
    Small = 4,

    /// <summary>Format standard (~260x260 px), recommandé pour le web.</summary>
    Medium = 8,

    /// <summary>Format haute densité (~400x400 px), idéal pour grands écrans.</summary>
    Large = 12
}

/// <summary>
/// Algorithme de hachage HMAC utilisé pour le calcul TOTP (RFC 6238).
/// </summary>
public enum TotpAlgorithm
{
    /// <summary>HMAC-SHA1 (standard universel Google/Microsoft Authenticator).</summary>
    Sha1,

    /// <summary>HMAC-SHA256 (sécurité renforcée).</summary>
    Sha256,

    /// <summary>HMAC-SHA512 (haute sécurité).</summary>
    Sha512
}

/// <summary>
/// Nombre de chiffres du code d'authentification temporaire.
/// </summary>
public enum TotpDigits
{
    /// <summary>Code standard à 6 chiffres.</summary>
    Six = 6,

    /// <summary>Code étendu à 8 chiffres.</summary>
    Eight = 8
}

/// <summary>
/// Raison précise d'un échec lors d'une opération Flash2Fa (sans exception).
/// </summary>
public enum Flash2FaError
{
    /// <summary>Aucune erreur, l'opération a réussi.</summary>
    None = 0,

    /// <summary>La clé secrète Base32 est vide, mal formée ou trop courte.</summary>
    InvalidSecret,

    /// <summary>Le nom de l'application (issuer) ou du compte est vide.</summary>
    InvalidAccountInfo,

    /// <summary>Les données dépassent la capacité maximale du QR Code (Version 10).</summary>
    PayloadTooLarge,

    /// <summary>Le buffer de destination fourni est trop petit.</summary>
    BufferTooSmall,

    /// <summary>Le nombre de codes de récupération demandé doit être compris entre 1 et 64.</summary>
    InvalidRecoveryCodeCount
}
