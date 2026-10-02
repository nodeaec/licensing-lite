using System;
using System.Globalization;
using System.Text.Json.Serialization;

namespace NodeAec.Licensing.Models;

/// <summary>
/// Represents a single product grant/authorization held by the Master Entitlements Lease.
/// </summary>
public class EntitlementItem
{
    [JsonPropertyName("slug")]
    public string Slug { get; set; } = string.Empty;

    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("licenseKey")]
    public string? LicenseKey { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = "perpetual";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "active";

    /// <summary>
    /// Token <c>granted</c> claim: the issuer only includes granted entitlements, but the
    /// value is honored by <see cref="IsActive"/> — <c>false</c> denies even when the
    /// rest of the item is valid. Missing in the token → defaults to <c>true</c>.
    /// </summary>
    [JsonPropertyName("granted")]
    public bool Granted { get; set; } = true;

    [JsonPropertyName("expiresAt")]
    public string? ExpiresAtString { get; set; }

    /// <summary>
    /// Deterministically parsed expiry: invariant culture with
    /// <see cref="DateTimeStyles.AssumeUniversal"/> — without an explicit offset the date
    /// counts as midnight UTC, not local midnight. Invalid/out-of-range → <c>null</c>.
    /// </summary>
    [JsonIgnore]
    public DateTimeOffset? ExpiresAt
    {
        get
        {
            if (string.IsNullOrWhiteSpace(ExpiresAtString)) return null;
            if (DateTimeOffset.TryParse(ExpiresAtString, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dt)) return dt;
            return null;
        }
    }

    [JsonPropertyName("maxActivations")]
    public int? MaxActivations { get; set; }

    [JsonPropertyName("activeActivations")]
    public int? ActiveActivations { get; set; }

    /// <summary>
    /// Whether the grant is active and valid for immediate use.
    /// </summary>
    public bool IsActive()
    {
        if (!Granted)
        {
            return false;
        }

        if (!string.Equals(Status, "active", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (ExpiresAt.HasValue && ExpiresAt.Value < DateTimeOffset.UtcNow)
        {
            return false;
        }

        return true;
    }
}
