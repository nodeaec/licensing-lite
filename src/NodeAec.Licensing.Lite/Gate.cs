using System;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using NodeAec.Licensing.Cryptography;
using NodeAec.Licensing.Hardware;
using NodeAec.Licensing.Storage;

namespace NodeAec.Licensing;

/// <summary>
/// Offline license verification for plugins in the Node.aec ecosystem.
/// Zero network calls: reads the local master lease (DPAPI) written by
/// the Node.aec Connector and checks the Ed25519 signature against the
/// compiled anchors before trusting any claim.
/// Never throws: every failure becomes a denied <see cref="Snapshot"/> (fail-closed).
/// </summary>
public static class Gate
{
    /// <summary>Clock-skew tolerance (seconds) accepted for the `iat` claim being in the future.</summary>
    private const long ClockSkewToleranceSeconds = 300;

    /// <summary>
    /// Validates whether the product identified by <paramref name="productSlug"/> holds an
    /// active grant on this workstation. Runs locally with no network access:
    /// verifies the lease Ed25519 signature and only then trusts the claims.
    /// Slug comparison uses <c>Trim()</c> + <c>OrdinalIgnoreCase</c>.
    /// </summary>
    public static Snapshot Validate(string productSlug)
    {
        if (string.IsNullOrWhiteSpace(productSlug))
        {
            return Snapshot.Failure("Slug do produto não informado para validação.");
        }

        string? jwtToken = LeaseStorage.LoadMasterLease();
        if (string.IsNullOrWhiteSpace(jwtToken))
        {
            return Snapshot.Failure("Nenhuma credencial do Node.aec encontrada nesta estação. Abra o Node.aec Connector na Ribbon para entrar com sua conta ou ativar sua licença.");
        }

        try
        {
            var payload = LeaseStorage.ParseJwtPayload(jwtToken);
            if (payload == null)
            {
                return Snapshot.Failure("Concessão corrompida ou estrutura inválida. Abra o Node.aec Connector para ressincronizar.");
            }

            // 0. Cryptographic verification (Ed25519 / RFC 8032): no claim is worth
            // anything before the signature checks out. A tampered, forged, or
            // differently-keyed file is rejected here, fail-closed.
            if (!LeaseSignatureVerifier.TryVerify(jwtToken, out _))
            {
                return Snapshot.Failure("A licença local não passou na verificação de segurança. Conecte-se à internet e clique em atualizar no Node.aec Connector.");
            }

            // 0.1 Token contract: only master leases issued by the Node.aec platform.
            if (!string.Equals(payload.Iss, "node-aec", StringComparison.Ordinal))
            {
                return Snapshot.Failure("Origem da licença local desconhecida. Conecte-se à internet e clique em atualizar no Node.aec Connector.");
            }

            if (!string.Equals(payload.Scope, "master-lease", StringComparison.OrdinalIgnoreCase))
            {
                return Snapshot.Failure("A licença local está em formato não suportado. Conecte-se à internet e clique em atualizar no Node.aec Connector.");
            }

            // 0.1b Audience (RFC 7519): the issuer marks whom the token is intended for.
            // Missing or from another flow → does not validate at the plugin gate (fail-closed).
            if (!HasPlatformAudience(payload.Aud))
            {
                return Snapshot.Failure("A licença local não foi emitida para este add-in. Conecte-se à internet e clique em atualizar no Node.aec Connector.");
            }

            // 0.2 Defense against a backdated clock: issuance in the future beyond the
            // 5-minute tolerance indicates a tampered date.
            if (payload.Iat > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ClockSkewToleranceSeconds)
            {
                return Snapshot.Failure("A data da licença local é inválida. Confira a data e hora deste computador e tente novamente.");
            }

            // 1. Hardware binding validation (machine ID). Without a readable MachineGuid
            //    there is no way to confirm the lease belongs to this machine: fail closed.
            if (!HardwareId.TryGetMachineId(out string currentMachineId, out _))
            {
                return Snapshot.Failure("Não foi possível identificar esta máquina (MachineGuid do Windows indisponível). Contate o suporte Node.aec.");
            }

            if (!string.Equals(payload.Mid, currentMachineId, StringComparison.OrdinalIgnoreCase))
            {
                return Snapshot.Failure("A concessão de licenças foi emitida para outra estação de trabalho (Hardware ID divergente).");
            }

            // 2. Offline grace deadline validation. Without a plausible `exp`,
            //    `IsExpired` is already true; the message distinguishes an unreadable deadline
            //    from an elapsed one so it never prints 01/01/1970 or formats a null.
            if (payload.IsExpired)
            {
                return payload.ExpiresAt is { } exp
                    ? Snapshot.Failure($"O prazo de tolerância offline expirou em {exp:dd/MM/yyyy}. Conecte-se à internet para sincronizar.")
                    : Snapshot.Failure("O prazo da licença local não pôde ser lido. Conecte-se à internet e clique em atualizar no Node.aec Connector.");
            }

            // 3. Validation of the specific product in the grant list
            var item = payload.Entitlements?.FirstOrDefault(e =>
                string.Equals(e.Slug, productSlug.Trim(), StringComparison.OrdinalIgnoreCase));

            if (item == null)
            {
                return Snapshot.Failure($"O produto '{productSlug}' não consta nas licenças ativas desta conta. Adquira ou ative no catálogo Node.aec.");
            }

            if (!item.IsActive())
            {
                if (string.Equals(item.Status, "seat_limit_reached", StringComparison.OrdinalIgnoreCase))
                {
                    return Snapshot.Failure($"O limite de computadores simultâneos para '{item.Name}' foi atingido.");
                }

                if (item.ExpiresAt.HasValue && item.ExpiresAt.Value < DateTimeOffset.UtcNow)
                {
                    return Snapshot.Failure($"A licença ou período de teste de '{item.Name}' expirou em {item.ExpiresAt.Value:dd/MM/yyyy}.");
                }

                return Snapshot.Failure($"A licença de '{item.Name}' está com status '{item.Status}'.");
            }

            return Snapshot.Success(item.Type, item.LicenseKey, item.Name, item.ExpiresAt);
        }
        catch
        {
            return Snapshot.Failure("Não foi possível verificar a licença local. Abra o Node.aec Connector para ressincronizar.");
        }
    }

    /// <summary>
    /// Checks whether the lease audience (<c>aud</c>) includes one of the
    /// platform audiences. Accepts a single string or an array (RFC 7519); a
    /// missing/foreign claim → denies.
    /// </summary>
    /// <param name="aud">Deserialized <c>aud</c> claim value, or null when absent.</param>
    /// <returns><c>true</c> when the lease targets the Node.aec platform.</returns>
    internal static bool HasPlatformAudience(JsonElement? aud)
    {
        if (aud is not { } element)
        {
            return false;
        }

        if (element.ValueKind == JsonValueKind.String)
        {
            return IsPlatformAudience(element.GetString());
        }

        if (element.ValueKind == JsonValueKind.Array)
        {
            foreach (var entry in element.EnumerateArray())
            {
                if (entry.ValueKind == JsonValueKind.String && IsPlatformAudience(entry.GetString()))
                {
                    return true;
                }
            }
        }

        return false;
    }

    /// <summary>Compares an audience for exact equality with the known platform values.</summary>
    private static bool IsPlatformAudience(string? value) =>
        string.Equals(value, "node-aec-desktop", StringComparison.Ordinal) ||
        string.Equals(value, "node-aec-plugin", StringComparison.Ordinal);

    /// <summary>
    /// Invokes the Node.aec Connector management window when loaded in the AppDomain.
    /// Silent no-op when the Hub is absent.
    /// </summary>
    public static void OpenConnector()
    {
        try
        {
            var uiType = Type.GetType("NodeAec.Connector.UI.ConnectorWindow, NodeAec.Connector");
            if (uiType != null)
            {
                var openMethod = uiType.GetMethod("Open", BindingFlags.Public | BindingFlags.Static);
                openMethod?.Invoke(null, null);
            }
        }
        catch
        {
            // Silent when the connector add-in is not in the same process
        }
    }
}

/// <summary>
/// Immutable result of <see cref="Gate.Validate(string)"/>: only the
/// <see cref="Success"/>/<see cref="Failure"/> factories build one and no property
/// changes afterwards — a consumer cannot rewrite a gate result.
/// </summary>
public sealed class Snapshot
{
    private Snapshot(bool isLicensed, string message, string? productName, string? licenseType, string? licenseKey, DateTimeOffset? expiresAt)
    {
        IsLicensed = isLicensed;
        Message = message;
        ProductName = productName;
        LicenseType = licenseType;
        LicenseKey = licenseKey;
        ExpiresAt = expiresAt;
    }

    /// <summary>Single branch point: <c>true</c> only with an active, verified license.</summary>
    public bool IsLicensed { get; }

    /// <summary>Verbatim PT-BR message (same taxonomy as the Connector); display it to the user.</summary>
    public string Message { get; }

    /// <summary>Display name of the grant; <c>null</c> on failure.</summary>
    public string? ProductName { get; }

    /// <summary>Grant type (e.g. <c>perpetual</c>); <c>null</c> on failure.</summary>
    public string? LicenseType { get; }

    /// <summary>License key; <c>null</c> on failure.</summary>
    public string? LicenseKey { get; }

    /// <summary>Grant expiry; <c>null</c> = no claim / perpetual.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    public static Snapshot Success(string type, string? key, string? name, DateTimeOffset? expiresAt, string message = "Licença ativa e verificada.")
    {
        return new Snapshot(true, message, name, type, key, expiresAt);
    }

    public static Snapshot Failure(string message)
    {
        return new Snapshot(false, message, null, null, null, null);
    }
}
