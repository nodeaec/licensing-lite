using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace NodeAec.Licensing.Models;

/// <summary>
/// Claim layout of the Master Entitlements Lease JWT issued by the Node.aec platform.
/// </summary>
public class MasterLeasePayload
{
    [JsonPropertyName("iss")]
    public string? Iss { get; set; }

    [JsonPropertyName("sub")]
    public string? Sub { get; set; }

    [JsonPropertyName("mid")]
    public string? Mid { get; set; }

    [JsonPropertyName("scope")]
    public string? Scope { get; set; }

    /// <summary>
    /// Token audience (<c>aud</c>): whom the lease was issued for. Kept as
    /// <see cref="JsonElement"/> so a single string or an array (RFC 7519) is accepted
    /// without failing the whole payload deserialization when the shape differs.
    /// </summary>
    [JsonPropertyName("aud")]
    public JsonElement? Aud { get; set; }

    [JsonPropertyName("iat")]
    public long Iat { get; set; }

    [JsonPropertyName("exp")]
    public long Exp { get; set; }

    [JsonPropertyName("entitlements")]
    public List<EntitlementItem> Entitlements { get; set; } = new();

    /// <summary>
    /// Expiry instant (<c>exp</c>). Unix seconds outside the plausible range
    /// (0 = missing, negative, or ≥ 01/01/2100) yield <c>null</c> instead of
    /// throwing <see cref="ArgumentOutOfRangeException"/> — <c>FromUnixTimeSeconds</c>
    /// is only called after the range check.
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset? ExpiresAt => IsPlausibleUnixSeconds(Exp)
        ? DateTimeOffset.FromUnixTimeSeconds(Exp)
        : null;

    /// <summary>
    /// Issuance instant (<c>iat</c>), with the same safe range as <see cref="ExpiresAt"/>.
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset? IssuedAt => IsPlausibleUnixSeconds(Iat)
        ? DateTimeOffset.FromUnixTimeSeconds(Iat)
        : null;

    /// <summary>
    /// Offline grace deadline. Without a plausible <c>exp</c> the lease is treated as
    /// expired (fail-closed): a legitimate signed lease always carries an in-range
    /// <c>exp</c>, so an unreadable deadline never grants access.
    /// </summary>
    [JsonIgnore]
    public bool IsExpired => ExpiresAt is null || ExpiresAt < DateTimeOffset.UtcNow;

    /// <summary>Upper bound for plausible unix seconds: 01/01/2100.</summary>
    private const long MaxPlausibleUnixSeconds = 4102444800;

    /// <summary>
    /// Unix seconds valid for date claims: strictly positive (0 = missing)
    /// and before 01/01/2100 (tampered clock / corrupt value).
    /// </summary>
    private static bool IsPlausibleUnixSeconds(long seconds)
        => seconds > 0 && seconds < MaxPlausibleUnixSeconds;
}
