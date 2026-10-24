using System;
using System.ComponentModel;
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
    /// <remarks>
    /// Never throws: every failure comes back as a denied <see cref="Snapshot"/> whose
    /// <see cref="Snapshot.Reason"/> names the cause. Each call reads and verifies the lease
    /// from disk (no cache), so call it once per command execution and never from
    /// <c>IExternalCommandAvailability</c>. Safe to call from any thread.
    /// </remarks>
    /// <param name="productSlug">Product slug registered on Node.aec (case-insensitive).</param>
    /// <returns>The immutable decision; read <see cref="Snapshot.IsLicensed"/> first.</returns>
    public static Snapshot Validate(string productSlug)
    {
        if (string.IsNullOrWhiteSpace(productSlug))
        {
            return Snapshot.Denied(GateReason.MissingProductSlug);
        }

        string? jwtToken = LeaseStorage.LoadMasterLease();
        if (string.IsNullOrWhiteSpace(jwtToken))
        {
            return Snapshot.Denied(GateReason.NoLease);
        }

        try
        {
            var payload = LeaseStorage.ParseJwtPayload(jwtToken);
            if (payload == null)
            {
                return Snapshot.Denied(GateReason.CorruptLease);
            }

            // 0. Cryptographic verification (Ed25519 / RFC 8032): no claim is worth
            // anything before the signature checks out. A tampered, forged, or
            // differently-keyed file is rejected here, fail-closed.
            if (!LeaseSignatureVerifier.TryVerify(jwtToken, out _))
            {
                return Snapshot.Denied(GateReason.SignatureInvalid);
            }

            // 0.1 Token contract: only master leases issued by the Node.aec platform.
            if (!string.Equals(payload.Iss, "node-aec", StringComparison.Ordinal))
            {
                return Snapshot.Denied(GateReason.UnknownIssuer);
            }

            if (!string.Equals(payload.Scope, "master-lease", StringComparison.OrdinalIgnoreCase))
            {
                return Snapshot.Denied(GateReason.UnsupportedFormat);
            }

            // 0.1b Audience (RFC 7519): the issuer marks whom the token is intended for.
            // Missing or from another flow → does not validate at the plugin gate (fail-closed).
            if (!HasPlatformAudience(payload.Aud))
            {
                return Snapshot.Denied(GateReason.WrongAudience);
            }

            // 0.2 Defense against a backdated clock: issuance in the future beyond the
            // 5-minute tolerance indicates a tampered date.
            if (payload.Iat > DateTimeOffset.UtcNow.ToUnixTimeSeconds() + ClockSkewToleranceSeconds)
            {
                return Snapshot.Denied(GateReason.ClockInvalid);
            }

            // 1. Hardware binding validation (machine ID). Without a readable MachineGuid
            //    there is no way to confirm the lease belongs to this machine: fail closed.
            if (!HardwareId.TryGetMachineId(out string currentMachineId, out _))
            {
                return Snapshot.Denied(GateReason.MachineIdUnavailable);
            }

            if (!string.Equals(payload.Mid, currentMachineId, StringComparison.OrdinalIgnoreCase))
            {
                return Snapshot.Denied(GateReason.MachineMismatch);
            }

            // 2. Offline grace deadline validation. Without a plausible `exp`,
            //    `IsExpired` is already true; the message distinguishes an unreadable deadline
            //    from an elapsed one so it never prints 01/01/1970 or formats a null.
            if (payload.IsExpired)
            {
                return payload.ExpiresAt is { } exp
                    ? Snapshot.Denied(GateReason.OfflineGraceExpired, date: exp)
                    : Snapshot.Denied(GateReason.LeaseExpiryUnreadable);
            }

            // 3. Validation of the specific product in the grant list
            var item = payload.Entitlements?.FirstOrDefault(e =>
                string.Equals(e.Slug, productSlug.Trim(), StringComparison.OrdinalIgnoreCase));

            if (item == null)
            {
                return Snapshot.Denied(GateReason.ProductNotFound, subject: productSlug);
            }

            if (!item.IsActive())
            {
                if (string.Equals(item.Status, "seat_limit_reached", StringComparison.OrdinalIgnoreCase))
                {
                    return Snapshot.Denied(GateReason.SeatLimitReached, subject: item.Name);
                }

                if (item.ExpiresAt.HasValue && item.ExpiresAt.Value < DateTimeOffset.UtcNow)
                {
                    return Snapshot.Denied(GateReason.LicenseExpired, subject: item.Name, date: item.ExpiresAt.Value);
                }

                return Snapshot.Denied(GateReason.LicenseInactive, subject: item.Name, status: item.Status);
            }

            return Snapshot.Granted(item.Type, item.LicenseKey, item.Name, item.ExpiresAt);
        }
        catch
        {
            return Snapshot.Denied(GateReason.VerificationError);
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
/// Immutable result of <see cref="Gate.Validate(string)"/>: no property changes after it
/// is built, so a consumer cannot rewrite a gate result.
/// </summary>
public sealed class Snapshot
{
    private readonly string? _customMessage;
    private readonly string? _subject;
    private readonly string? _status;
    private readonly DateTimeOffset? _date;

    private Snapshot(
        bool isLicensed,
        GateReason reason,
        string? productName,
        string? licenseType,
        string? licenseKey,
        DateTimeOffset? expiresAt,
        string? customMessage = null,
        string? subject = null,
        string? status = null,
        DateTimeOffset? date = null)
    {
        IsLicensed = isLicensed;
        Reason = reason;
        ProductName = productName;
        LicenseType = licenseType;
        LicenseKey = licenseKey;
        ExpiresAt = expiresAt;
        _customMessage = customMessage;
        _subject = subject;
        _status = status;
        _date = date;
    }

    /// <summary>Single branch point: <c>true</c> only with an active, verified license.</summary>
    public bool IsLicensed { get; }

    /// <summary>
    /// The one specific reason for the decision; <see cref="GateReason.Licensed"/> on success.
    /// Use it to log or to react to a specific case, never to decide whether to run: that is
    /// <see cref="IsLicensed"/>.
    /// </summary>
    public GateReason Reason { get; }

    /// <summary>
    /// End-user text in Brazilian Portuguese, the same as <c>GetMessage(MessageLanguage.Portuguese)</c>.
    /// It names the one specific reason and the next step: show it as-is.
    /// </summary>
    public string Message => GetMessage(MessageLanguage.Portuguese);

    /// <summary>Display name of the grant; <c>null</c> on failure.</summary>
    public string? ProductName { get; }

    /// <summary>Grant type (e.g. <c>perpetual</c>); <c>null</c> on failure.</summary>
    public string? LicenseType { get; }

    /// <summary>
    /// The user's license key (<c>NAEC-…</c>); <c>null</c> on failure. A secret of the end
    /// user: never log it or send it anywhere.
    /// </summary>
    public string? LicenseKey { get; }

    /// <summary>Grant expiry; <c>null</c> = no claim / perpetual.</summary>
    public DateTimeOffset? ExpiresAt { get; }

    /// <summary>
    /// End-user text for <see cref="Reason"/> in <paramref name="language"/>. Like
    /// <see cref="Message"/>, it names the one specific reason and the next step.
    /// </summary>
    /// <param name="language">Language of the text.</param>
    /// <returns>The message, never <c>null</c>.</returns>
    public string GetMessage(MessageLanguage language) =>
        _customMessage ?? GateMessages.Format(Reason, language, _subject, _status, _date);

    /// <summary>Licensed result built by the gate.</summary>
    internal static Snapshot Granted(string type, string? key, string? name, DateTimeOffset? expiresAt) =>
        new Snapshot(true, GateReason.Licensed, name, type, key, expiresAt);

    /// <summary>Denied result built by the gate; the arguments fill the message for <paramref name="reason"/>.</summary>
    internal static Snapshot Denied(GateReason reason, string? subject = null, string? status = null, DateTimeOffset? date = null) =>
        new Snapshot(false, reason, null, null, null, null, subject: subject, status: status, date: date);

    /// <summary>
    /// Builds a licensed result with a fixed message. Kept for compatibility with 0.1/0.2;
    /// a plugin has no reason to call it, because <see cref="Gate.Validate(string)"/> builds every result.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Snapshot Success(string type, string? key, string? name, DateTimeOffset? expiresAt, string message = "Licença ativa e verificada.")
    {
        // The default text stays translatable; only a caller-supplied text is fixed.
        string? custom = message == "Licença ativa e verificada." ? null : message;
        return new Snapshot(true, GateReason.Licensed, name, type, key, expiresAt, customMessage: custom);
    }

    /// <summary>
    /// Builds a denied result with a fixed message and <see cref="GateReason.VerificationError"/>.
    /// Kept for compatibility with 0.1/0.2; a plugin has no reason to call it.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public static Snapshot Failure(string message)
    {
        return new Snapshot(false, GateReason.VerificationError, null, null, null, null, customMessage: message);
    }
}
