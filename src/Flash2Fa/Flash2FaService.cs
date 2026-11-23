using System.Buffers;
using System.Text;
using System.Text.Unicode;
using Flash2Fa.Internal;

namespace Flash2Fa;

/// <summary>
/// Point d'entrée principal de Flash2Fa pour la gestion de la double authentification (2FA),
/// la génération de QR Codes (PNG/SVG) et la validation des codes TOTP et de récupération.
/// Garantie 100% sans exception (pattern Try) et 100% compatible Native AOT.
/// </summary>
public static class Flash2FaService
{
    private const int DefaultRenderBufferSize = 128 * 1024;

    /// <summary>
    /// Tente d'initialiser une nouvelle configuration 2FA complète pour un utilisateur :
    /// génère une clé secrète aléatoire, le QR Code en Base64 et les codes de récupération.
    /// </summary>
    /// <param name="issuer">Nom de l'application ou du service émetteur affiché dans l'application Authenticator.</param>
    /// <param name="accountName">Identifiant unique du compte utilisateur (ex: adresse email ou nom d'utilisateur).</param>
    /// <param name="setup">En cas de succès, contient la clé secrète Base32, le QR Code en Base64 et les codes de récupération.</param>
    /// <param name="error">Code d'erreur indiquant la raison de l'échec, ou <see cref="Flash2FaError.None"/> en cas de succès.</param>
    /// <param name="format">Format d'image souhaité pour le QR Code (<see cref="QrImageFormat.Png"/> par défaut).</param>
    /// <param name="options">Options de personnalisation visuelle du QR Code (taille, couleurs, forme, marge). Si <see langword="null"/>, utilise <see cref="QrCodeOptions.Default"/>.</param>
    /// <param name="recoveryCodeCount">Nombre de codes de récupération à générer (entre 1 et 64, 8 par défaut).</param>
    /// <param name="algorithm">Algorithme HMAC utilisé pour le calcul TOTP (<see cref="TotpAlgorithm.Sha1"/> par défaut).</param>
    /// <param name="digits">Nombre de chiffres des codes temporaires (<see cref="TotpDigits.Six"/> par défaut).</param>
    /// <param name="includeDataUriPrefix">Indique s'il faut inclure le préfixe <c>data:image/...;base64,</c> prêt pour une balise HTML <c>&lt;img&gt;</c>.</param>
    /// <returns><see langword="true"/> si la configuration a été générée avec succès ; sinon <see langword="false"/>.</returns>
    public static bool TryCreateSetup(
        string issuer,
        string accountName,
        out TwoFactorSetup setup,
        out Flash2FaError error,
        QrImageFormat format = QrImageFormat.Png,
        QrCodeOptions? options = null,
        int recoveryCodeCount = 8,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six,
        bool includeDataUriPrefix = true)
    {
        setup = default;

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(accountName))
        {
            error = Flash2FaError.InvalidAccountInfo;
            return false;
        }

        if (!RecoveryEngine.TryGenerate(recoveryCodeCount, out RecoveryCodes recoveryCodes))
        {
            error = Flash2FaError.InvalidRecoveryCodeCount;
            return false;
        }

        string secret = TotpEngine.GenerateSecret();
        if (!TryGenerateQrCodeBase64(secret, issuer, accountName, out string qrBase64, out error, format, options, algorithm, digits, includeDataUriPrefix))
        {
            return false;
        }

        setup = new TwoFactorSetup(secret, qrBase64, recoveryCodes);
        error = Flash2FaError.None;
        return true;
    }

    /// <summary>
    /// Tente de générer un QR Code encodé en Base64 à partir d'une clé secrète existante.
    /// </summary>
    /// <param name="secret">Clé secrète encodée en Base32.</param>
    /// <param name="issuer">Nom de l'application ou du service émetteur.</param>
    /// <param name="accountName">Identifiant du compte utilisateur.</param>
    /// <param name="qrCodeBase64">En cas de succès, chaîne Base64 représentant l'image du QR Code.</param>
    /// <param name="error">Code d'erreur indiquant la raison de l'échec, ou <see cref="Flash2FaError.None"/> en cas de succès.</param>
    /// <param name="format">Format d'image souhaité (<see cref="QrImageFormat.Png"/> ou <see cref="QrImageFormat.Svg"/>).</param>
    /// <param name="options">Options de personnalisation visuelle du QR Code. Si <see langword="null"/>, utilise <see cref="QrCodeOptions.Default"/>.</param>
    /// <param name="algorithm">Algorithme HMAC configuré pour ce compte (<see cref="TotpAlgorithm.Sha1"/> par défaut).</param>
    /// <param name="digits">Nombre de chiffres configuré pour ce compte (<see cref="TotpDigits.Six"/> par défaut).</param>
    /// <param name="includeDataUriPrefix">Indique s'il faut préfixer le résultat par <c>data:image/...;base64,</c>.</param>
    /// <returns><see langword="true"/> si le QR Code a été généré ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateQrCodeBase64(
        ReadOnlySpan<char> secret,
        string issuer,
        string accountName,
        out string qrCodeBase64,
        out Flash2FaError error,
        QrImageFormat format = QrImageFormat.Png,
        QrCodeOptions? options = null,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six,
        bool includeDataUriPrefix = true)
    {
        qrCodeBase64 = string.Empty;

        byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultRenderBufferSize);
        try
        {
            if (!TryGenerateQrCodeBytes(secret, issuer, accountName, buffer, out int bytesWritten, out error, format, options, algorithm, digits))
            {
                return false;
            }

            ReadOnlySpan<byte> imageBytes = buffer.AsSpan(0, bytesWritten);
            if (!includeDataUriPrefix)
            {
                qrCodeBase64 = Convert.ToBase64String(imageBytes);
                return true;
            }

            string prefix = format == QrImageFormat.Svg
                ? "data:image/svg+xml;base64,"
                : "data:image/png;base64,";

            int base64Length = ((bytesWritten + 2) / 3) * 4;
            qrCodeBase64 = string.Create(prefix.Length + base64Length, (prefix, buffer, bytesWritten), static (span, state) =>
            {
                state.prefix.AsSpan().CopyTo(span);
                Convert.TryToBase64Chars(state.buffer.AsSpan(0, state.bytesWritten), span[state.prefix.Length..], out _);
            });

            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Tente de générer le fichier image binaire brut (PNG ou SVG) du QR Code à partir d'une clé secrète existante.
    /// </summary>
    /// <param name="secret">Clé secrète encodée en Base32.</param>
    /// <param name="issuer">Nom de l'application ou du service émetteur.</param>
    /// <param name="accountName">Identifiant du compte utilisateur.</param>
    /// <param name="qrCodeBytes">En cas de succès, tableau d'octets contenant le fichier PNG ou SVG complet.</param>
    /// <param name="error">Code d'erreur indiquant la raison de l'échec, ou <see cref="Flash2FaError.None"/> en cas de succès.</param>
    /// <param name="format">Format d'image souhaité (<see cref="QrImageFormat.Png"/> ou <see cref="QrImageFormat.Svg"/>).</param>
    /// <param name="options">Options de personnalisation visuelle du QR Code. Si <see langword="null"/>, utilise <see cref="QrCodeOptions.Default"/>.</param>
    /// <param name="algorithm">Algorithme HMAC configuré pour ce compte.</param>
    /// <param name="digits">Nombre de chiffres configuré pour ce compte.</param>
    /// <returns><see langword="true"/> si le fichier binaire a été généré ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateQrCodeBytes(
        ReadOnlySpan<char> secret,
        string issuer,
        string accountName,
        out byte[] qrCodeBytes,
        out Flash2FaError error,
        QrImageFormat format = QrImageFormat.Png,
        QrCodeOptions? options = null,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        qrCodeBytes = [];

        byte[] buffer = ArrayPool<byte>.Shared.Rent(DefaultRenderBufferSize);
        try
        {
            if (!TryGenerateQrCodeBytes(secret, issuer, accountName, buffer, out int bytesWritten, out error, format, options, algorithm, digits))
            {
                return false;
            }

            qrCodeBytes = buffer.AsSpan(0, bytesWritten).ToArray();
            return true;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    /// <summary>
    /// Écrit directement le flux binaire (PNG ou SVG) du QR Code dans le buffer fourni sans allocation sur le tas.
    /// </summary>
    /// <param name="secret">Clé secrète encodée en Base32.</param>
    /// <param name="issuer">Nom de l'application ou du service émetteur.</param>
    /// <param name="accountName">Identifiant du compte utilisateur.</param>
    /// <param name="destination">Mémoire tampon cible dans laquelle écrire les octets de l'image.</param>
    /// <param name="bytesWritten">Nombre d'octets effectivement écrits dans <paramref name="destination"/>.</param>
    /// <param name="error">Code d'erreur indiquant la raison de l'échec, ou <see cref="Flash2FaError.None"/> en cas de succès.</param>
    /// <param name="format">Format d'image souhaité (<see cref="QrImageFormat.Png"/> ou <see cref="QrImageFormat.Svg"/>).</param>
    /// <param name="options">Options de personnalisation visuelle du QR Code. Si <see langword="null"/>, utilise <see cref="QrCodeOptions.Default"/>.</param>
    /// <param name="algorithm">Algorithme HMAC configuré pour ce compte.</param>
    /// <param name="digits">Nombre de chiffres configuré pour ce compte.</param>
    /// <returns><see langword="true"/> si l'image a été écrite dans <paramref name="destination"/> ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateQrCodeBytes(
        ReadOnlySpan<char> secret,
        string issuer,
        string accountName,
        Span<byte> destination,
        out int bytesWritten,
        out Flash2FaError error,
        QrImageFormat format = QrImageFormat.Png,
        QrCodeOptions? options = null,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        bytesWritten = 0;

        if (string.IsNullOrWhiteSpace(issuer) || string.IsNullOrWhiteSpace(accountName))
        {
            error = Flash2FaError.InvalidAccountInfo;
            return false;
        }

        if (!TotpEngine.IsValidSecret(secret))
        {
            error = Flash2FaError.InvalidSecret;
            return false;
        }

        Span<byte> uriUtf8Buffer = stackalloc byte[512];
        if (!TryBuildOtpAuthUriUtf8(secret, issuer, accountName, algorithm, digits, uriUtf8Buffer, out int uriLength))
        {
            error = Flash2FaError.PayloadTooLarge;
            return false;
        }

        Span<byte> matrixBuffer = stackalloc byte[QrMatrixBuilder.RequiredBufferSize];
        if (!QrMatrixBuilder.TryEncode(uriUtf8Buffer[..uriLength], matrixBuffer, out QrMatrix matrix))
        {
            error = Flash2FaError.PayloadTooLarge;
            return false;
        }

        QrCodeOptions resolvedOptions = options ?? QrCodeOptions.Default;

        bool rendered = format switch
        {
            QrImageFormat.Png => QrRenderers.TryRenderPng(in matrix, resolvedOptions, destination, out bytesWritten),
            QrImageFormat.Svg => QrRenderers.TryRenderSvg(in matrix, resolvedOptions, destination, out bytesWritten),
            _ => false
        };

        if (!rendered)
        {
            error = Flash2FaError.BufferTooSmall;
            return false;
        }

        error = Flash2FaError.None;
        return true;
    }

    /// <summary>
    /// Tente de générer le code d'authentification temporaire actuel (ex: 6 chiffres) à partir de la clé secrète.
    /// </summary>
    /// <param name="secret">Clé secrète encodée en Base32.</param>
    /// <param name="code">En cas de succès, chaîne contenant le code temporaire à 6 ou 8 chiffres.</param>
    /// <param name="algorithm">Algorithme HMAC utilisé (<see cref="TotpAlgorithm.Sha1"/> par défaut).</param>
    /// <param name="digits">Nombre de chiffres du code (<see cref="TotpDigits.Six"/> par défaut).</param>
    /// <returns><see langword="true"/> si la clé secrète est valide et que le code a été généré ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateCode(
        ReadOnlySpan<char> secret,
        out string code,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        return TryGenerateCode(secret, out code, out _, timestamp: null, algorithm, digits);
    }

    /// <summary>
    /// Tente de générer le code d'authentification temporaire à partir de la clé secrète et indique
    /// le nombre de secondes restantes avant son expiration (1 à 30s).
    /// </summary>
    /// <param name="secret">Clé secrète encodée en Base32.</param>
    /// <param name="code">En cas de succès, chaîne contenant le code temporaire à 6 ou 8 chiffres.</param>
    /// <param name="remainingSeconds">Nombre de secondes restantes avant le prochain renouvellement du code (entre 1 et 30).</param>
    /// <param name="timestamp">Horodatage de référence optionnel. Si <see langword="null"/>, utilise <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <param name="algorithm">Algorithme HMAC utilisé (<see cref="TotpAlgorithm.Sha1"/> par défaut).</param>
    /// <param name="digits">Nombre de chiffres du code (<see cref="TotpDigits.Six"/> par défaut).</param>
    /// <returns><see langword="true"/> si la clé secrète est valide et que le code a été généré ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateCode(
        ReadOnlySpan<char> secret,
        out string code,
        out int remainingSeconds,
        DateTimeOffset? timestamp = null,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        Span<char> codeBuffer = stackalloc char[8];
        if (!TotpEngine.TryGenerateCode(secret, codeBuffer, out int charsWritten, out remainingSeconds, timestamp, algorithm, digits))
        {
            code = string.Empty;
            return false;
        }

        code = new string(codeBuffer[..charsWritten]);
        return true;
    }

    /// <summary>
    /// Écrit le code d'authentification temporaire directement dans un buffer <see cref="Span{T}"/> sans aucune allocation mémoire.
    /// </summary>
    /// <param name="secret">Clé secrète encodée en Base32.</param>
    /// <param name="destination">Mémoire tampon cible d'au moins 6 ou 8 caractères.</param>
    /// <param name="charsWritten">Nombre de caractères écrits dans <paramref name="destination"/>.</param>
    /// <param name="remainingSeconds">Nombre de secondes restantes avant l'expiration du code (entre 1 et 30).</param>
    /// <param name="timestamp">Horodatage de référence optionnel. Si <see langword="null"/>, utilise <see cref="DateTimeOffset.UtcNow"/>.</param>
    /// <param name="algorithm">Algorithme HMAC utilisé (<see cref="TotpAlgorithm.Sha1"/> par défaut).</param>
    /// <param name="digits">Nombre de chiffres du code (<see cref="TotpDigits.Six"/> par défaut).</param>
    /// <returns><see langword="true"/> si le code a été écrit avec succès ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateCode(
        ReadOnlySpan<char> secret,
        Span<char> destination,
        out int charsWritten,
        out int remainingSeconds,
        DateTimeOffset? timestamp = null,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        return TotpEngine.TryGenerateCode(secret, destination, out charsWritten, out remainingSeconds, timestamp, algorithm, digits);
    }

    /// <summary>
    /// Vérifie la validité d'un code temporaire saisi par l'utilisateur avec tolérance de dérive d'horloge.
    /// </summary>
    /// <param name="secret">Clé secrète Base32 de l'utilisateur.</param>
    /// <param name="code">Code à 6 ou 8 chiffres saisi par l'utilisateur.</param>
    /// <param name="matchedTimeStep">Créneau temporel ayant validé le code (à enregistrer pour empêcher la réutilisation du même code).</param>
    /// <param name="toleranceSteps">Nombre de créneaux de 30s tolérés avant et après l'heure actuelle (1 par défaut = ±30s).</param>
    /// <param name="algorithm">Algorithme HMAC attendu (<see cref="TotpAlgorithm.Sha1"/> par défaut).</param>
    /// <param name="digits">Nombre de chiffres attendu (<see cref="TotpDigits.Six"/> par défaut).</param>
    /// <returns><see langword="true"/> si le code est valide ; sinon <see langword="false"/>.</returns>
    public static bool VerifyCode(
        ReadOnlySpan<char> secret,
        ReadOnlySpan<char> code,
        out long matchedTimeStep,
        int toleranceSteps = 1,
        TotpAlgorithm algorithm = TotpAlgorithm.Sha1,
        TotpDigits digits = TotpDigits.Six)
    {
        return TotpEngine.VerifyCode(secret, code, out matchedTimeStep, toleranceSteps, algorithm, digits);
    }

    /// <summary>
    /// Indique si la chaîne fournie correspond à une clé secrète Base32 syntaxiquement valide et suffisamment longue.
    /// </summary>
    /// <param name="secret">Chaîne de caractères Base32 à valider.</param>
    /// <returns><see langword="true"/> si la clé secrète est valide ; sinon <see langword="false"/>.</returns>
    public static bool IsValidSecret(ReadOnlySpan<char> secret)
    {
        return TotpEngine.IsValidSecret(secret);
    }

    /// <summary>
    /// Tente de générer un nouveau jeu de clés de récupération lisibles et leurs empreintes SHA-256.
    /// </summary>
    /// <param name="count">Nombre de codes à générer (doit être compris entre 1 et 64).</param>
    /// <param name="recoveryCodes">En cas de succès, contient les codes en clair et leurs empreintes SHA-256.</param>
    /// <returns><see langword="true"/> si <paramref name="count"/> est valide et que les codes ont été générés ; sinon <see langword="false"/>.</returns>
    public static bool TryGenerateRecoveryCodes(int count, out RecoveryCodes recoveryCodes)
    {
        return RecoveryEngine.TryGenerate(count, out recoveryCodes);
    }

    /// <summary>
    /// Génère un jeu standard de 8 clés de récupération lisibles et leurs empreintes SHA-256.
    /// </summary>
    /// <returns>Structure <see cref="RecoveryCodes"/> contenant les 8 codes en clair et leurs empreintes hachées.</returns>
    public static RecoveryCodes GenerateRecoveryCodes()
    {
        RecoveryEngine.TryGenerate(8, out RecoveryCodes codes);
        return codes;
    }

    /// <summary>
    /// Vérifie en temps constant un code de récupération saisi par l'utilisateur par rapport à une empreinte SHA-256 stockée.
    /// </summary>
    /// <param name="userInputCode">Code saisi par l'utilisateur (insensible à la casse, aux tirets et aux espaces).</param>
    /// <param name="storedHash">Empreinte SHA-256 hexadécimale (64 caractères) stockée en base de données.</param>
    /// <returns><see langword="true"/> si le code correspond à l'empreinte ; sinon <see langword="false"/>.</returns>
    public static bool VerifyRecoveryCode(ReadOnlySpan<char> userInputCode, ReadOnlySpan<char> storedHash)
    {
        return RecoveryEngine.VerifyCode(userInputCode, storedHash);
    }

    /// <summary>
    /// Vérifie en temps constant un code de récupération par rapport à une liste d'empreintes stockées.
    /// </summary>
    /// <param name="userInputCode">Code saisi par l'utilisateur (insensible à la casse, aux tirets et aux espaces).</param>
    /// <param name="storedHashes">Collection des empreintes SHA-256 encore valides pour ce compte.</param>
    /// <returns>L'index du code valide dans <paramref name="storedHashes"/> (0..N-1) afin de pouvoir l'invalider immédiatement, ou -1 si aucun ne correspond.</returns>
    public static int VerifyRecoveryCode(ReadOnlySpan<char> userInputCode, ReadOnlySpan<string> storedHashes)
    {
        return RecoveryEngine.VerifyCode(userInputCode, storedHashes);
    }

private static bool TryBuildOtpAuthUriUtf8(
        ReadOnlySpan<char> secret,
        string issuer,
        string accountName,
        TotpAlgorithm algorithm,
        TotpDigits digits,
        Span<byte> destination,
        out int bytesWritten)
    {
        bytesWritten = 0;

        ReadOnlySpan<char> trimmedIssuer = issuer.AsSpan().Trim();
        ReadOnlySpan<char> trimmedAccount = accountName.AsSpan().Trim();

        // Conversion UTF-8 sur la pile avant encodage pourcentage RFC 3986
        Span<byte> rawIssuerUtf8 = stackalloc byte[128];
        Span<byte> rawAccountUtf8 = stackalloc byte[128];

        if (Encoding.UTF8.GetByteCount(trimmedIssuer) > rawIssuerUtf8.Length ||
            Encoding.UTF8.GetByteCount(trimmedAccount) > rawAccountUtf8.Length)
        {
            return false;
        }

        int rawIssuerLen = Encoding.UTF8.GetBytes(trimmedIssuer, rawIssuerUtf8);
        int rawAccountLen = Encoding.UTF8.GetBytes(trimmedAccount, rawAccountUtf8);

        Span<byte> encodedIssuer = stackalloc byte[384];
        Span<byte> encodedAccount = stackalloc byte[384];

        if (!TryUrlEncodeUtf8(rawIssuerUtf8[..rawIssuerLen], encodedIssuer, out int encIssuerLen) ||
            !TryUrlEncodeUtf8(rawAccountUtf8[..rawAccountLen], encodedAccount, out int encAccountLen))
        {
            return false;
        }

        // Nettoyage de la clé secrète directement en octets ASCII majuscules
        Span<byte> cleanSecret = stackalloc byte[256];
        int cleanSecretLen = 0;
        foreach (char c in secret)
        {
            if (c is ' ' or '-' or '=')
            {
                continue;
            }
            if (cleanSecretLen >= cleanSecret.Length)
            {
                return false;
            }
            cleanSecret[cleanSecretLen++] = (byte)char.ToUpperInvariant(c);
        }

        ReadOnlySpan<byte> algoBytes = algorithm switch
        {
            TotpAlgorithm.Sha1 => "SHA1"u8,
            TotpAlgorithm.Sha256 => "SHA256"u8,
            TotpAlgorithm.Sha512 => "SHA512"u8,
            _ => "SHA1"u8
        };

        ReadOnlySpan<byte> digitsBytes = digits == TotpDigits.Eight ? "8"u8 : "6"u8;

        // Assemblage direct sans aucune allocation de string
        int pos = 0;
        if (!TryAppend("otpauth://totp/"u8, destination, ref pos) ||
            !TryAppend(encodedIssuer[..encIssuerLen], destination, ref pos) ||
            !TryAppend(":"u8, destination, ref pos) ||
            !TryAppend(encodedAccount[..encAccountLen], destination, ref pos) ||
            !TryAppend("?secret="u8, destination, ref pos) ||
            !TryAppend(cleanSecret[..cleanSecretLen], destination, ref pos) ||
            !TryAppend("&issuer="u8, destination, ref pos) ||
            !TryAppend(encodedIssuer[..encIssuerLen], destination, ref pos) ||
            !TryAppend("&algorithm="u8, destination, ref pos) ||
            !TryAppend(algoBytes, destination, ref pos) ||
            !TryAppend("&digits="u8, destination, ref pos) ||
            !TryAppend(digitsBytes, destination, ref pos) ||
            !TryAppend("&period=30"u8, destination, ref pos))
        {
            return false;
        }

        bytesWritten = pos;
        return true;

        static bool TryAppend(ReadOnlySpan<byte> source, Span<byte> dest, ref int offset)
        {
            if (dest.Length - offset < source.Length)
            {
                return false;
            }
            source.CopyTo(dest[offset..]);
            offset += source.Length;
            return true;
        }
    }

    private static bool TryUrlEncodeUtf8(ReadOnlySpan<byte> utf8Input, Span<byte> destination, out int bytesWritten)
    {
        bytesWritten = 0;
        ReadOnlySpan<byte> hexChars = "0123456789ABCDEF"u8;

        foreach (byte b in utf8Input)
        {
            // Caractères non réservés RFC 3986 : A-Z, a-z, 0-9, '-', '.', '_', '~'
            bool isUnreserved =
                (uint)(b - 'A') <= ('Z' - 'A') ||
                (uint)(b - 'a') <= ('z' - 'a') ||
                (uint)(b - '0') <= ('9' - '0') ||
                b is (byte)'-' or (byte)'.' or (byte)'_' or (byte)'~';

            if (isUnreserved)
            {
                if (bytesWritten >= destination.Length)
                {
                    return false;
                }
                destination[bytesWritten++] = b;
            }
            else
            {
                if (destination.Length - bytesWritten < 3)
                {
                    return false;
                }
                destination[bytesWritten++] = (byte)'%';
                destination[bytesWritten++] = hexChars[b >> 4];
                destination[bytesWritten++] = hexChars[b & 0x0F];
            }
        }

        return true;
    }
}