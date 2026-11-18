# ⚡ Flash2Fa

[![.NET](https://img.shields.io/badge/.NET-10.0-512BD4?logo=dotnet)](https://dotnet.microsoft.com/)
[![Native AOT](https://img.shields.io/badge/Native%20AOT-100%25%20Ready-success)](#pourquoi-choisir-flash2fa-)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-blue)](#pourquoi-choisir-flash2fa-)
[![Zero Allocation](https://img.shields.io/badge/Allocation-0%20B%20Hot%20Path-orange)](#benchmarks--performances)
[![RFC 6238](https://img.shields.io/badge/RFC-6238%20%2F%204226-lightgrey)](#)

**Flash2Fa** est une bibliothèque .NET moderne, ultra-rapide et sans aucune dépendance externe pour intégrer l'authentification à deux facteurs (**2FA / TOTP**), les **codes de récupération** et la **génération native de QR Codes (PNG et SVG)** dans vos applications.

---

## 📑 Sommaire

- [Pourquoi choisir Flash2Fa ?](#-pourquoi-choisir-flash2fa-)
- [Installation](#-installation)
- [Démarrage rapide (Pour débuter en 2 minutes)](#-démarrage-rapide-pour-débuter-en-2-minutes)
  - [1. Activer la 2FA pour un utilisateur](#1-activer-la-2fa-pour-un-utilisateur)
  - [2. Vérifier le code saisi lors de la connexion](#2-vérifier-le-code-saisi-lors-de-la-connexion)
  - [3. Utiliser un code de récupération (secours)](#3-utiliser-un-code-de-récupération-secours)
- [Personnalisation des QR Codes (PNG & SVG)](#-personnalisation-des-qr-codes-png--svg)
- [Utilisation avancée : Mode Zéro Allocation (`Span<T>`)](#-utilisation-avancée--mode-zéro-allocation-spant)
- [Exemple complet « Monde Réel » (API Minimal .NET)](#-exemple-complet--monde-réel--api-minimal-net)
- [Référence rapide de l'API](#-référence-rapide-de-lapi)
- [Benchmarks & Performances](#-benchmarks--performances)
- [Bonnes pratiques de sécurité](#-bonnes-pratiques-de-sécurité)

---

## 💡 Pourquoi choisir Flash2Fa ?

Mettre en place la 2FA en .NET oblige souvent à assembler plusieurs bibliothèques (une pour le TOTP, une autre pour générer des QR Codes, et `SkiaSharp` ou `ImageSharp` pour le rendu d'image), ce qui alourdit le projet et pose des problèmes sous **Linux, Docker ou Native AOT**.

**Flash2Fa réunit tout en un seul package léger :**

| Atout | Ce que ça change pour votre projet |
| :--- | :--- |
| **🚫 Zéro dépendance** | Tout est écrit en C# pur (HMAC, Base32, matrice QR Reed-Solomon, compression PNG 1-bit et tracé SVG). Aucune DLL native (`libSkiaSharp`, etc.) à déployer. |
| **🚀 100 % Native AOT** | Zéro réflexion dynamique. Compilé et certifié sans aucun avertissement avec `PublishAot=true` et `TrimMode=full`. |
| **⚡ Zéro allocation (`0 B`)** | Les opérations critiques (vérification TOTP, codes de secours, génération QR dans un buffer `Span<T>`) n'allouent **aucun octet** sur le tas managé. |
| **🛡️ Zéro exception** | Toutes les API publiques suivent le pattern `Try` : retour booléen clair et code d'erreur explicite (`Flash2FaError`). |
| **🎨 QR Codes sûrs & stylés** | Export **SVG** ou **PNG** avec personnalisation (taille, couleurs, `Square` / `Rounded` / `Dots`) et **correction automatique du contraste**. |
| **🔐 Sécurité intégrée** | Comparaisons en temps constant (vectorisées SIMD / sans branchement), aléatoire via `RandomNumberGenerator` et hachage SHA-256 des codes de secours. |

---

## 📦 Installation

Via la ligne de commande .NET :

```bash
dotnet add package Flash2Fa
```

Ou dans votre fichier `.csproj` :

```xml
<ItemGroup>
  <PackageReference Include="Flash2Fa" Version="1.0.0"/>
</ItemGroup>
```

---

## 🚀 Démarrage rapide (Pour débuter en 2 minutes)

### 1. Activer la 2FA pour un utilisateur

Lorsqu'un utilisateur souhaite activer la double authentification sur son compte, appelez `TryCreateSetup` (ici en **SVG**), puis utilisez `TryGenerateQrCodeBytes` si vous souhaitez servir ou enregistrer directement le fichier **sans encodage Base64** :

```csharp
using Flash2Fa;

// Génère la clé secrète, le QR Code (SVG) et 8 codes de secours
if (Flash2FaService.TryCreateSetup("MonApplication", "alice@exemple.fr", out TwoFactorSetup setup, out Flash2FaError error, format: QrImageFormat.Svg))
{
    // 1. À stocker de manière sécurisée (chiffrée) dans votre base de données pour cet utilisateur :
    string secretToStoreInDb = setup.Secret;

    // 2. À afficher UNE SEULE FOIS à l'utilisateur pour qu'il les note (ex: "A7K9-M2P4") :
    string[] codesToShowOnce = setup.RecoveryCodes.PlainCodes;

    // 3. À enregistrer en base de données (empreintes SHA-256 uniquement, jamais en clair !) :
    string[] hashesToStoreInDb = setup.RecoveryCodes.HashedCodes;

    // 4. Télécharger / sauvegarder directement le fichier SVG brut (sans Base64) :
    if (Flash2FaService.TryGenerateQrCodeBytes(setup.Secret, "MonApplication", "alice@exemple.fr", out byte[] svgBytes, out _, format: QrImageFormat.Svg))
    {
        File.WriteAllBytes("qrcode-2fa.svg", svgBytes);
    }
}
else
{
    Console.WriteLine($"Impossible de créer la configuration 2FA : {error}");
}
```

### 2. Vérifier le code saisi lors de la connexion

Lorsque l'utilisateur saisit les 6 chiffres affichés sur son téléphone (Google Authenticator, Apple Mots de passe, Bitwarden, Authy...) :

```csharp
using Flash2Fa;

string userSecretFromDb = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
string codeTypedByUser = "482910";

// Par défaut, tolère un décalage d'horloge de ±30 secondes (1 créneau avant/après)
if (Flash2FaService.VerifyCode(userSecretFromDb, codeTypedByUser, out long matchedTimeStep))
{
    // ✅ Code valide !
    // Conseil sécurité : vérifiez que matchedTimeStep > lastUsedTimeStepFromDb
    // afin d'empêcher qu'un même code soit utilisé deux fois dans la même fenêtre de 30s.
    Console.WriteLine($"Connexion autorisée (créneau temporel : {matchedTimeStep})");
}
else
{
    // ❌ Code invalide ou expiré
    Console.WriteLine("Code d'authentification incorrect.");
}
```

### 3. Utiliser un code de récupération (secours)

Si l'utilisateur a perdu son téléphone, il peut saisir l'un de ses codes de secours (insensible aux majuscules, minuscules, espaces ou tirets) :

```csharp
using Flash2Fa;

string inputFromUser = "a7k9 m2p4"; // Fonctionne même en minuscules ou sans tiret
string[] userStoredHashes = GetUserRecoveryHashesFromDb();

int matchedIndex = Flash2FaService.VerifyRecoveryCode(inputFromUser, userStoredHashes);

if (matchedIndex >= 0)
{
    // ✅ Code de secours valide !
    // Supprimez immédiatement l'empreinte à l'index 'matchedIndex' en base de données (usage unique)
    RemoveRecoveryHashAt(matchedIndex);
    Console.WriteLine("Connexion de secours réussie !");
}
else
{
    Console.WriteLine("Code de récupération invalide.");
}
```

---

## 🎨 Personnalisation des QR Codes (PNG & SVG)

Vous pouvez adapter l'apparence du QR Code à la charte graphique de votre application tout en conservant une lisibilité garantie :

```csharp
using Flash2Fa;

// Définition des couleurs (avec validation sans exception)
QrColor.TryFromHex("#38BDF8", out QrColor bleuCiel);
QrColor.TryFromHex("#0F172A", out QrColor fondSombre);

var options = new QrCodeOptions(
    Size: QrCodeSize.Medium,            // Small (4px/module), Medium (8px), Large (12px)
    Foreground: bleuCiel,
    Background: fondSombre,
    Shape: QrModuleShape.Dots,          // Square (carrés), Rounded (arrondis), Dots (points circulaires)
    QuietZone: 2,                       // Marge blanche/de fond autour du QR Code
    EnforceReadableContrast: true       // Corrige automatiquement si le contraste est trop faible pour une caméra
);

// Export en fichier binaire SVG (ou PNG avec QrImageFormat.Png)
if (Flash2FaService.TryGenerateQrCodeBytes(
    secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP",
    issuer: "MonApp",
    accountName: "alice@exemple.fr",
    out byte[] svgBytes,
    out Flash2FaError error,
    format: QrImageFormat.Svg,
    options: options))
{
    File.WriteAllBytes("qrcode.svg", svgBytes);
}
```

---

## ⚡ Utilisation avancée : Mode Zéro Allocation (`Span<T>`)

Pour les serveurs à très fort trafic ou les environnements temps réel, **Flash2Fa** permet d'écrire les codes TOTP et les fichiers PNG/SVG directement dans vos propres buffers (`stackalloc` ou `ArrayPool<byte>`) sans allouer un seul octet sur le tas :

```csharp
using System.Buffers;
using Flash2Fa;

// 1. Générer un code TOTP sur la pile (0 B alloué) — prévoir 8 chars si TotpDigits.Eight
Span<char> codeBuffer = stackalloc char[6];
if (Flash2FaService.TryGenerateCode(secret, codeBuffer, out int charsWritten, out int remainingSeconds))
{
    ReadOnlySpan<char> code = codeBuffer[..charsWritten];
    // Utilisez 'code' directement sans création de string
}

// 2. Générer un QR Code PNG dans un buffer loué (0 B alloué)
byte[] renderBuffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
try
{
    if (Flash2FaService.TryGenerateQrCodeBytes(
        secret, "MonApp", "alice@exemple.fr",
        destination: renderBuffer,
        out int bytesWritten,
        out Flash2FaError error,
        format: QrImageFormat.Png))
    {
        await responseStream.WriteAsync(renderBuffer.AsMemory(0, bytesWritten));
    }
}
finally
{
    ArrayPool<byte>.Shared.Return(renderBuffer);
}
```

---

## 🏗️ Exemple complet « Monde Réel » (API Minimal .NET)

Voici un exemple complet d'intégration dans une API Web ASP.NET Core gérant :
1. L'activation de la 2FA (`POST /2fa/enable`)
2. Le téléchargement direct du QR Code en fichier SVG (`GET /2fa/qrcode`) sans Base64
3. La confirmation initiale avec protection anti-rejeu (`POST /2fa/confirm`)
4. La connexion par code TOTP ou code de secours (`POST /2fa/verify`)

```csharp
using System.Runtime.InteropServices;
using Flash2Fa;

var builder = WebApplication.CreateBuilder(args);
var app = builder.Build();

// Simulation d'un stockage utilisateur en base de données
var userStore = new UserSecurityRecord
{
    Email = "alice@exemple.fr",
    IsTwoFactorEnabled = false
};

// ÉTAPE 1 : L'utilisateur demande l'activation de la 2FA
app.MapPost("/2fa/enable", () =>
{
    if (!Flash2FaService.TryCreateSetup(
        issuer: "FlashBank",
        accountName: userStore.Email,
        out TwoFactorSetup setup,
        out Flash2FaError error,
        format: QrImageFormat.Svg,
        options: new QrCodeOptions(Shape: QrModuleShape.Rounded)))
    {
        return Results.BadRequest(new { Error = error.ToString() });
    }

    // On sauvegarde le secret en attente de confirmation + les empreintes des codes de secours
    userStore.PendingSecret = setup.Secret;
    userStore.RecoveryCodeHashes = [.. setup.RecoveryCodes.HashedCodes];

    return Results.Ok(new
    {
        QrCodeDownloadUrl = "/2fa/qrcode",             // Lien direct vers le fichier SVG téléchargeable
        ManualEntryKey = setup.Secret,                 // Si l'utilisateur ne peut pas scanner
        RecoveryCodes = setup.RecoveryCodes.PlainCodes // À afficher une seule fois !
    });
});

// ÉTAPE 1 bis : Téléchargement direct du fichier QR Code SVG (sans Base64)
app.MapGet("/2fa/qrcode", () =>
{
    string? secret = userStore.PendingSecret ?? userStore.ActiveSecret;
    if (string.IsNullOrEmpty(secret))
        return Results.NotFound("Aucune clé 2FA configurée.");

    if (!Flash2FaService.TryGenerateQrCodeBytes(
        secret,
        issuer: "FlashBank",
        accountName: userStore.Email,
        out byte[] svgBytes,
        out Flash2FaError error,
        format: QrImageFormat.Svg,
        options: new QrCodeOptions(Shape: QrModuleShape.Rounded)))
    {
        return Results.BadRequest(new { Error = error.ToString() });
    }

    return Results.File(svgBytes, "image/svg+xml", "qrcode-2fa.svg");
});

// ÉTAPE 2 : L'utilisateur scanne le QR Code et valide son premier code pour activer la 2FA
app.MapPost("/2fa/confirm", (VerifyRequest req) =>
{
    if (string.IsNullOrEmpty(userStore.PendingSecret))
        return Results.BadRequest("Aucune configuration 2FA en attente.");

    if (!Flash2FaService.VerifyCode(userStore.PendingSecret, req.Code, out long timeStep))
        return Results.Unauthorized();

    // Activation définitive
    userStore.ActiveSecret = userStore.PendingSecret;
    userStore.PendingSecret = null;
    userStore.LastUsedTimeStep = timeStep;
    userStore.IsTwoFactorEnabled = true;

    return Results.Ok(new { Message = "Double authentification activée avec succès." });
});

// ÉTAPE 3 : Vérification lors d'une connexion (accepte un code TOTP ou un code de secours)
app.MapPost("/2fa/verify", (VerifyRequest req) =>
{
    if (!userStore.IsTwoFactorEnabled || userStore.ActiveSecret is null)
        return Results.BadRequest("2FA non activée.");

    // 1. Tentative avec un code TOTP à 6 chiffres
    if (Flash2FaService.VerifyCode(userStore.ActiveSecret, req.Code, out long matchedStep))
    {
        // Protection anti-rejeu : interdire de réutiliser un code déjà validé
        if (matchedStep <= userStore.LastUsedTimeStep)
            return Results.Unauthorized();

        userStore.LastUsedTimeStep = matchedStep;
        return Results.Ok(new { Authenticated = true, Method = "TOTP" });
    }

    // 2. Sinon, tentative avec un code de récupération (secours) sans allocation via AsSpan
    int recoveryIdx = Flash2FaService.VerifyRecoveryCode(req.Code, CollectionsMarshal.AsSpan(userStore.RecoveryCodeHashes));
    if (recoveryIdx >= 0)
    {
        // Invalidation immédiate du code de secours utilisé (usage unique)
        userStore.RecoveryCodeHashes.RemoveAt(recoveryIdx);
        return Results.Ok(new
        {
            Authenticated = true,
            Method = "RecoveryCode",
            RemainingRecoveryCodes = userStore.RecoveryCodeHashes.Count
        });
    }

    return Results.Unauthorized();
});

app.Run();

record VerifyRequest(string Code);

class UserSecurityRecord
{
    public string Email { get; set; } = "";
    public bool IsTwoFactorEnabled { get; set; }
    public string? PendingSecret { get; set; }
    public string? ActiveSecret { get; set; }
    public long LastUsedTimeStep { get; set; }
    public List<string> RecoveryCodeHashes { get; set; } = [];
}
```

---

## 📚 Référence rapide de l'API

Toutes les méthodes sont exposées sur la classe statique `Flash2FaService` :

| Méthode | Rôle |
| :--- | :--- |
| `TryCreateSetup(...)` | Génère en un appel la clé secrète Base32, le QR Code (Base64) et les codes de récupération. |
| `VerifyCode(...)` | Vérifie un code TOTP à 6 ou 8 chiffres avec tolérance d'horloge et renvoie le créneau validé. |
| `TryGenerateCode(...)` | Calcule le code TOTP actuel (et les secondes restantes avant expiration) en `string` ou `Span<char>`. |
| `TryGenerateQrCodeBase64(...)` | Génère un QR Code PNG ou SVG prêt à afficher en HTML (`data:image/...;base64,`). |
| `TryGenerateQrCodeBytes(...)` | Génère les octets bruts d'un fichier PNG ou SVG (allocation `byte[]` ou écriture directe dans `Span<byte>`). |
| `TryGenerateRecoveryCodes(...)` / `GenerateRecoveryCodes()` | Génère entre 1 et 64 codes de secours lisibles (8 par défaut, format `XXXX-XXXX`) et leurs empreintes SHA-256. |
| `VerifyRecoveryCode(...)` | Vérifie un code de secours en temps constant contre une empreinte ou une liste d'empreintes. |
| `IsValidSecret(...)` | Vérifie qu'une clé Base32 est syntaxiquement valide et suffisamment longue. |

---

## 📊 Benchmarks & Performances

Mesures réalisées avec **BenchmarkDotNet** sur **.NET 10.0** (Release) :

| Méthode | Temps moyen (Mean) | Débit théorique (1 cœur) | Mémoire allouée (`Allocated`) |
| :--- | :---: | :---: | :---: |
| **`Recovery: VerifyCode (8 hashes)`** | **256,2 ns** | ~3 900 000 ops/s | **0 B** (`-`) |
| **`TOTP: TryGenerateCode (Span)`** | **692,7 ns** | ~1 440 000 ops/s | **0 B** (`-`) |
| **`TOTP: VerifyCode (Hot Path)`** | **1 942,8 ns** | ~514 000 ops/s | **0 B** (`-`) |
| **`QR Code: PNG 1-bit (Span)`** | **142,2 µs** | ~7 030 QR/s | **0 B** (`-`) |
| **`QR Code: SVG Custom Dots (Span)`** | **145,2 µs** | ~6 880 QR/s | **0 B** (`-`) |
| **`Setup: CreateSetup Complet (PNG + 8 Recovery)`** | **165,2 µs** | ~6 050 setups/s | **2 096 B** *(objets retournés)* |

### 🔍 Comment lire ces résultats ?

* **`0 B` (`-`) sur les 5 opérations critiques :** Lorsqu'un utilisateur se connecte (`VerifyCode`), utilise un code de secours ou que votre serveur génère un QR Code dans un buffer, **pas un seul octet n'est alloué sur le tas**. Vos serveurs web ne subissent aucune pause du Garbage Collector, même sous forte charge.
* **256 nanosecondes pour vérifier 8 codes de secours :** Normaliser la saisie utilisateur, calculer son empreinte SHA-256 et comparer les 8 empreintes en temps constant prend un quart de microseconde.
* **~0,14 milliseconde pour un QR Code complet :** L'encodage de l'URI `otpauth://`, le calcul des codes correcteurs d'erreurs Reed-Solomon, l'évaluation des 8 masques ISO et la compression PNG Zlib (ou le tracé SVG vectoriel) s'exécutent en moins d'un sixième de milliseconde en pur C#.
* **`2 096 B` sur `TryCreateSetup` :** Ce sont uniquement les objets finaux créés pour votre application (la chaîne Base64 du QR Code et les deux tableaux de 8 `string` pour les codes de secours).

---

## 🔒 Bonnes pratiques de sécurité

1. **Ne stockez jamais les codes de secours en clair :** Enregistrez uniquement `setup.RecoveryCodes.HashedCodes` (les empreintes SHA-256) dans votre base de données et supprimez chaque empreinte dès qu'elle est utilisée.
2. **Protégez la clé secrète en base de données :** Chiffrez `setup.Secret` au repos (par exemple via ASP.NET Core Data Protection ou AES-GCM) avant de l'enregistrer dans votre table utilisateurs.
3. **Empêchez la réutilisation d'un code TOTP (Anti-Replay) :** Un code TOTP est valide pendant 30 secondes. Stockez le `matchedTimeStep` retourné par `VerifyCode` et refusez toute tentative dont le `matchedTimeStep` est inférieur ou égal au dernier validé.
4. **Limitez les tentatives (Rate Limiting) :** Protégez votre endpoint `/2fa/verify` contre la force brute (ex. maximum 5 tentatives par minute par compte).