using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;

namespace NodeAec.Licensing.Cryptography;

/// <summary>
/// Verifies the Ed25519 (RFC 8032) signature of lease tokens issued by the Node.aec platform
/// before any claim is trusted. Anchor-only mode: the only candidate keys are the
/// anchors compiled into <see cref="TrustedAnchors"/>. There is no environment-variable
/// override (an intentional difference from the Connector, which is the operations Hub).
/// Always fails closed: with no usable anchor or an invalid signature, the lease
/// is not accepted.
/// </summary>
public static class LeaseSignatureVerifier
{
    /// <summary>Signature algorithm accepted on leases (EdDSA / Ed25519).</summary>
    public const string AcceptedAlgorithm = "EdDSA";

    /// <summary>
    /// Public verification anchors (base64 SPKI Ed25519). The list supports N/N+1
    /// rotation: during a rotation it holds the new and the old key; afterwards the
    /// old one is removed.
    /// No private key exists in this repository.
    /// </summary>
    public static readonly string[] TrustedAnchors =
    {
        "MCowBQYDK2VwAyEArMYcaZMAlBeimfR6twrHZndEWOSaIHlSURYFhTjalMg=",
    };

    /// <summary>Raw Ed25519 key size in bytes.</summary>
    private const int RawKeySize = 32;

    /// <summary>
    /// Test anchor injected via <see cref="UseTestAnchorForTests"/> (same assembly
    /// or test assembly via <c>InternalsVisibleTo</c>). When non-null, it replaces
    /// <see cref="TrustedAnchors"/> as the sole candidate — tests sign with an
    /// ephemeral pair and inject the matching public key without touching the real
    /// release anchor.
    /// Null = production behavior. Never used outside tests.
    /// </summary>
    private static string? s_testAnchorOverride;

    /// <summary>
    /// Replaces the verification anchors with the given SPKI (test-only use).
    /// </summary>
    /// <param name="spkiBase64">Test Ed25519 public SPKI key in base64.</param>
    internal static void UseTestAnchorForTests(string spkiBase64) => s_testAnchorOverride = spkiBase64;

    /// <summary>Restores the compiled production anchors (test-only use).</summary>
    internal static void ClearTestAnchorOverride() => s_testAnchorOverride = null;
    /// <summary>Ed25519 signature size in bytes.</summary>
    private const int SignatureSize = 64;

    /// <summary>Fixed DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410).</summary>
    private static readonly byte[] SpkiEd25519Prefix =
    {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    };

    /// <summary>
    /// Granular signature-verification outcome. Lets the caller distinguish
    /// "a key is available and the signature does not check out" (firm rejection)
    /// from "there is no key to verify with" (unavailability).
    /// </summary>
    public enum VerificationOutcome
    {
        /// <summary>The Ed25519 signature checks out against an anchor.</summary>
        Verified,

        /// <summary>No usable anchor exists.</summary>
        NoKeysAvailable,

        /// <summary>Malformed token, unaccepted algorithm, or signature not confirmed by the anchors.</summary>
        Rejected,
    }

    /// <summary>
    /// Verifies the Ed25519 signature of a lease JWT in <c>header.payload.signature</c> form.
    /// </summary>
    /// <param name="jwt">Raw JWT token.</param>
    /// <param name="reason">Human-readable failure reason when the return is <c>false</c> (for logging; never display internally).</param>
    /// <returns><c>true</c> only when the header is EdDSA and the signature checks out against an anchor.</returns>
    public static bool TryVerify(string? jwt, out string? reason)
    {
        return Evaluate(jwt, out reason) == VerificationOutcome.Verified;
    }

    /// <summary>
    /// Evaluates the lease signature, distinguishing confirmation, anchor
    /// unavailability, and rejection.
    /// </summary>
    /// <param name="jwt">Raw lease JWT in <c>header.payload.signature</c> form.</param>
    /// <param name="reason">Human-readable outcome reason (for logging; never display internally).</param>
    /// <returns>Verification outcome — see <see cref="VerificationOutcome"/>.</returns>
    public static VerificationOutcome Evaluate(string? jwt, out string? reason)
    {
        reason = null;

        if (string.IsNullOrWhiteSpace(jwt))
        {
            reason = "token ausente";
            return VerificationOutcome.Rejected;
        }

        string[] parts = jwt.Trim().Split('.');
        if (parts.Length != 3)
        {
            reason = "estrutura JWT inválida";
            return VerificationOutcome.Rejected;
        }

        if (!TryReadHeader(parts[0], out string? algorithm, out reason))
        {
            return VerificationOutcome.Rejected;
        }

        if (!string.Equals(algorithm, AcceptedAlgorithm, StringComparison.Ordinal))
        {
            reason = $"algoritmo não suportado ({algorithm})";
            return VerificationOutcome.Rejected;
        }

        byte[]? signature = TryFromBase64Url(parts[2]);
        if (signature == null || signature.Length != SignatureSize)
        {
            reason = "assinatura em formato inválido";
            return VerificationOutcome.Rejected;
        }

        var candidates = LoadAnchorKeys();
        if (candidates.Count == 0)
        {
            reason = "âncora pública de verificação indisponível";
            return VerificationOutcome.NoKeysAvailable;
        }

        byte[] data = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");
        foreach (var candidate in candidates)
        {
            if (VerifySignature(data, signature, candidate))
            {
                reason = null;
                return VerificationOutcome.Verified;
            }
        }

        reason = "assinatura não corresponde à âncora de verificação";
        return VerificationOutcome.Rejected;
    }

    /// <summary>
    /// Decodes every usable anchor from <see cref="TrustedAnchors"/>.
    /// Invalid entries are skipped individually; when none decodes, the
    /// list comes back empty (fail-closed at the caller).
    /// </summary>
    private static List<byte[]> LoadAnchorKeys()
    {
        // Test hook: the override replaces the compiled list as the sole candidate.
        // Invalid override → empty list → fail-closed (NoKeysAvailable) at the caller.
        if (s_testAnchorOverride != null)
        {
            var single = new List<byte[]>(1);
            if (TryDecodeSpkiBase64(s_testAnchorOverride, out byte[] raw, out _))
            {
                single.Add(raw);
            }
            return single;
        }

        var keys = new List<byte[]>(TrustedAnchors.Length);
        foreach (var anchor in TrustedAnchors)
        {
            if (TryDecodeSpkiBase64(anchor, out byte[] raw, out _))
            {
                keys.Add(raw);
            }
        }
        return keys;
    }

    /// <summary>
    /// Decodes an Ed25519 base64 public SPKI key into the 32 raw curve bytes.
    /// </summary>
    /// <param name="spkiBase64">SPKI key in base64 (44 DER bytes total).</param>
    /// <param name="rawKey">32-byte raw key when the return is <c>true</c>.</param>
    /// <param name="reason">Human-readable failure reason when the return is <c>false</c>.</param>
    /// <returns><c>true</c> when the SPKI key has the expected Ed25519 shape.</returns>
    public static bool TryDecodeSpkiBase64(string? spkiBase64, out byte[] rawKey, out string? reason)
    {
        rawKey = Array.Empty<byte>();

        byte[]? der = null;
        try
        {
            der = string.IsNullOrWhiteSpace(spkiBase64) ? null : Convert.FromBase64String(spkiBase64.Trim());
        }
        catch (FormatException)
        {
            reason = "chave SPKI não é base64 válido";
            return false;
        }

        if (der == null)
        {
            reason = "chave SPKI vazia";
            return false;
        }

        if (der.Length != SpkiEd25519Prefix.Length + RawKeySize)
        {
            reason = "chave SPKI com tamanho inesperado";
            return false;
        }

        for (int i = 0; i < SpkiEd25519Prefix.Length; i++)
        {
            if (der[i] != SpkiEd25519Prefix[i])
            {
                reason = "chave SPKI não é Ed25519";
                return false;
            }
        }

        // Explicit copy instead of a range slice (`der[i..]`), which requires System.Index/
        // System.Range — types missing on .NET Framework 4.8 (Revit 2023/2024).
        rawKey = new byte[RawKeySize];
        Array.Copy(der, SpkiEd25519Prefix.Length, rawKey, 0, RawKeySize);
        reason = null;
        return true;
    }

    /// <summary>
    /// Decodes the JWT header and extracts <c>alg</c>. <c>kid</c> is not read: the only
    /// trust source is the compiled anchors, so the header does not take part in trust.
    /// </summary>
    private static bool TryReadHeader(string headerB64, out string? algorithm, out string? reason)
    {
        algorithm = null;

        byte[]? headerBytes = TryFromBase64Url(headerB64);
        if (headerBytes == null)
        {
            reason = "header JWT inválido";
            return false;
        }

        try
        {
            using var doc = JsonDocument.Parse(Encoding.UTF8.GetString(headerBytes));
            var root = doc.RootElement;
            algorithm = root.TryGetProperty("alg", out var alg) && alg.ValueKind == JsonValueKind.String
                ? alg.GetString()
                : null;
        }
        catch (JsonException)
        {
            reason = "header JWT não é JSON válido";
            return false;
        }

        if (string.IsNullOrWhiteSpace(algorithm))
        {
            reason = "header JWT sem algoritmo";
            return false;
        }

        reason = null;
        return true;
    }

    /// <summary>Runs the Ed25519 check with the given raw key.</summary>
    private static bool VerifySignature(byte[] data, byte[] signature, byte[] rawKey)
    {
        try
        {
            var signer = new Ed25519Signer();
            signer.Init(false, new Ed25519PublicKeyParameters(rawKey, 0));
            signer.BlockUpdate(data, 0, data.Length);
            return signer.VerifySignature(signature);
        }
        catch (Exception)
        {
            // A malformed key must never take validation down: it simply does not match.
            return false;
        }
    }

    /// <summary>Converts base64url (padded or not) to bytes, or <c>null</c> when invalid.</summary>
    private static byte[]? TryFromBase64Url(string input)
    {
        if (string.IsNullOrEmpty(input)) return null;

        string base64 = input.Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
            case 1: return null;
        }

        try
        {
            return Convert.FromBase64String(base64);
        }
        catch (FormatException)
        {
            return null;
        }
    }
}
