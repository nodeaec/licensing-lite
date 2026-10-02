using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NodeAec.Licensing.Cryptography;
using NodeAec.Licensing.Hardware;
using NodeAec.Licensing.Models;
using NodeAec.Licensing.Storage;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace NodeAec.Licensing.Lite.Tests;

/// <summary>
/// Port de <c>TestHelpers</c> do revit-connector: fabrica Master Lease JWTs realmente
/// assinados (Ed25519/BouncyCastle) com os mesmos vetores da RFC 8032.
/// A chave de teste é efêmera e só existe aqui — a âncora real de release jamais entra
/// como privada; o token de teste verifica contra a pública correspondente injetada via
/// <see cref="LeaseSignatureVerifier.UseTestAnchorForTests"/> (internal, visível por
/// <c>InternalsVisibleTo</c>).
/// </summary>
public static class TestHelpers
{
    /// <summary>
    /// Semente Ed25519 do vetor de teste 1 da RFC 8032 (chave pública conhecida:
    /// d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a).
    /// Determinística: tokens de teste são sempre assinados com a mesma chave.
    /// </summary>
    public static readonly byte[] Rfc8032TestSeed = Convert.FromHexString(
        "9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60");

    /// <summary>Chave pública esperada da semente acima (vetor da RFC 8032).</summary>
    public static readonly byte[] Rfc8032TestPublicKey = Convert.FromHexString(
        "D75A980182B10AB7D54BFED3C964073A0EE172F3DAA62325AF021A68F707511A");

    public const string TestKeyId = "node-aec-test-1";

    /// <summary>Slug padrão das concessões de teste.</summary>
    public const string TestSlug = "revit-automator";

    /// <summary>
    /// MachineGuid fictício fixo dos testes. O <c>mid</c> válido é o SHA-256 dele
    /// (<see cref="TestMachineId"/>); o leitor real é substituído por escopo.
    /// </summary>
    public const string TestMachineGuid = "11111111-2222-3333-4444-555555555555";

    /// <summary>Prefixo DER de um SPKI Ed25519 (RFC 8410).</summary>
    private static readonly byte[] SpkiEd25519Prefix =
    {
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    };

    /// <summary>
    /// Âncora pública de teste (SPKI base64 da chave RFC 8032): valor injetado via
    /// <c>UseTestAnchorForTests</c> pelos testes que verificam assinatura.
    /// </summary>
    public static string TestAnchorSpkiBase64 { get; } = CreateTestAnchorSpki();

    private static string CreateTestAnchorSpki()
    {
        byte[] der = new byte[SpkiEd25519Prefix.Length + Rfc8032TestPublicKey.Length];
        SpkiEd25519Prefix.CopyTo(der, 0);
        Rfc8032TestPublicKey.CopyTo(der, SpkiEd25519Prefix.Length);
        return Convert.ToBase64String(der);
    }

    private static Ed25519PrivateKeyParameters TestPrivateKey => new(Rfc8032TestSeed, 0);

    /// <summary>SHA-256 em hex minúsculo — mesma derivação de <c>HardwareId</c>.</summary>
    public static string Sha256HexLower(string input)
    {
        using var sha = SHA256.Create();
        byte[] hash = sha.ComputeHash(Encoding.UTF8.GetBytes(input));
        return BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
    }

    /// <summary>Machine ID correspondente ao <see cref="TestMachineGuid"/>.</summary>
    public static string TestMachineId => Sha256HexLower(TestMachineGuid);

    /// <summary>Concessão ativa padrão para o <see cref="TestSlug"/>.</summary>
    public static List<EntitlementItem> DefaultEntitlements() => new()
    {
        new EntitlementItem
        {
            Slug = TestSlug,
            Name = "Revit Automator",
            LicenseKey = "NAEC-TEST-1",
            Type = "perpetual",
            Status = "active",
            Granted = true,
        },
    };

    /// <summary>
    /// Gera um Master Entitlements Lease JWT <b>realmente assinado</b> com a chave de teste
    /// (EdDSA), no mesmo formato emitido pela API Node.aec. Cada claim tem override para
    /// os casos negativos exercerem exatamente uma falha por vez.
    /// </summary>
    public static string CreateMasterLeaseJwt(
        string? mid = null,
        DateTimeOffset? expiresAt = null,
        List<EntitlementItem>? entitlements = null,
        string iss = "node-aec",
        string scope = "master-lease",
        object? aud = null,
        bool omitAud = false,
        long? iatOverride = null,
        long? expOverride = null,
        Ed25519PrivateKeyParameters? privateKey = null,
        string sub = "usr_test")
    {
        long exp = expOverride ?? (expiresAt ?? DateTimeOffset.UtcNow.AddDays(30)).ToUnixTimeSeconds();
        var payload = new Dictionary<string, object?>
        {
            ["iss"] = iss,
            ["sub"] = sub,
            ["mid"] = mid ?? TestMachineId,
            ["scope"] = scope,
            ["iat"] = iatOverride ?? DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            ["exp"] = exp,
            ["entitlements"] = entitlements ?? DefaultEntitlements(),
        };
        if (!omitAud)
        {
            payload["aud"] = aud ?? new[] { "node-aec-desktop", "node-aec-plugin" };
        }

        return CreateSignedJwt(payload, privateKey ?? TestPrivateKey);
    }

    /// <summary>
    /// Monta um JWT assinado por uma chave Ed25519 arbitrária (para testes de rejeição
    /// de chave errada).
    /// </summary>
    public static string CreateSignedJwt(object payload, Ed25519PrivateKeyParameters privateKey, string? kid = TestKeyId)
    {
        var header = new Dictionary<string, object> { ["alg"] = "EdDSA", ["typ"] = "JWT" };
        if (kid != null) header["kid"] = kid;

        string headerBase64 = ToBase64Url(JsonSerializer.Serialize(header));
        string payloadBase64 = ToBase64Url(JsonSerializer.Serialize(payload));

        var signer = new Ed25519Signer();
        signer.Init(true, privateKey);
        byte[] message = Encoding.ASCII.GetBytes($"{headerBase64}.{payloadBase64}");
        signer.BlockUpdate(message, 0, message.Length);
        byte[] signature = signer.GenerateSignature();

        return $"{headerBase64}.{payloadBase64}.{EncodeBase64Url(signature)}";
    }

    /// <summary>Chave privada efêmera de atacante (semente arbitrária, nunca a de teste).</summary>
    public static Ed25519PrivateKeyParameters AttackerPrivateKey(string seedText)
    {
        using var sha = SHA256.Create();
        return new Ed25519PrivateKeyParameters(sha.ComputeHash(Encoding.UTF8.GetBytes(seedText)), 0);
    }

    /// <summary>
    /// Substitui o leitor do MachineGuid durante o escopo e restaura leitor + cache ao final
    /// (use sempre com <c>using</c>). A suíte roda com paralelismo desabilitado, então o
    /// leitor global pode ser trocado sem risco de corrida.
    /// </summary>
    public static IDisposable WithMachineGuid(string? machineGuid)
    {
        Func<string?> previous = HardwareId.MachineGuidReader;
        HardwareId.MachineGuidReader = () => machineGuid;
        HardwareId.ResetCacheForTests();

        return new MachineGuidScope(previous);
    }

    /// <summary>
    /// Injeta a âncora pública de teste durante o escopo e restaura as âncoras compiladas
    /// ao final (use sempre com <c>using</c>).
    /// </summary>
    public static IDisposable WithTestAnchor()
    {
        LeaseSignatureVerifier.UseTestAnchorForTests(TestAnchorSpkiBase64);
        return new AnchorScope();
    }

    /// <summary>Converte bytes em base64url sem padding (formato de segmentos JWT).</summary>
    public static string EncodeBase64Url(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .Replace("+", "-")
            .Replace("/", "_")
            .TrimEnd('=');
    }

    private sealed class MachineGuidScope : IDisposable
    {
        private readonly Func<string?> _previous;

        public MachineGuidScope(Func<string?> previous) => _previous = previous;

        public void Dispose()
        {
            HardwareId.MachineGuidReader = _previous;
            HardwareId.ResetCacheForTests();
        }
    }

    private sealed class AnchorScope : IDisposable
    {
        public void Dispose() => LeaseSignatureVerifier.ClearTestAnchorOverride();
    }

    private static string ToBase64Url(string input) => EncodeBase64Url(Encoding.UTF8.GetBytes(input));
}
