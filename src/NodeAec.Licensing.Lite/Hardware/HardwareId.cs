using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace NodeAec.Licensing.Hardware;

/// <summary>
/// Canonical hardware-identifier (machine ID) provider: SHA-256 of the
/// Windows <c>MachineGuid</c>, as 64 lowercase hex characters.
/// Without a readable <c>MachineGuid</c> the provider fails closed: it never
/// degrades to a weaker identifier.
/// </summary>
public static class HardwareId
{
    private static string? _cachedMachineId;

    /// <summary>
    /// Windows <c>MachineGuid</c> registry reader. Replaceable by tests only
    /// (same assembly): null/empty makes the provider fail closed.
    /// </summary>
    internal static Func<string?> MachineGuidReader { get; set; } = ReadMachineGuidFromRegistry;

    /// <summary>
    /// Tries to get this machine's identifier (lowercase hex SHA-256, 64 characters).
    /// </summary>
    /// <param name="machineId">Canonical identifier when the return is <c>true</c>.</param>
    /// <param name="reason">Human-readable unavailability reason when the return is <c>false</c>.</param>
    /// <returns><c>true</c> when the MachineGuid was read and the hash derived.</returns>
    public static bool TryGetMachineId(out string machineId, out string? reason)
    {
        string? cached = _cachedMachineId;
        if (cached != null && cached.Length > 0)
        {
            machineId = cached;
            reason = null;
            return true;
        }

        string? guid = MachineGuidReader();
        if (string.IsNullOrWhiteSpace(guid))
        {
            machineId = string.Empty;
            reason = "MachineGuid do Windows indisponível (registro ilegível ou sistema não-Windows)";
            return false;
        }

        _cachedMachineId = ComputeMachineId(guid);
        machineId = _cachedMachineId;
        reason = null;
        return true;
    }

    /// <summary>
    /// Derives the canonical machine ID from a <c>MachineGuid</c>: SHA-256 of the (trimmed)
    /// GUID as lowercase hex. The 64-character shape cannot change — it is what the
    /// stored leases reference in the <c>mid</c> claim.
    /// </summary>
    /// <param name="machineGuid"><c>HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid</c> value.</param>
    /// <returns>SHA-256 hash as 64 lowercase hexadecimal characters.</returns>
    internal static string ComputeMachineId(string machineGuid)
    {
        using var sha = SHA256.Create();
        var bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(machineGuid.Trim()));

        // BitConverter produces the hex text on every target framework (Convert.ToHexString needs .NET 5+).
        return BitConverter.ToString(bytes).Replace("-", string.Empty).ToLowerInvariant();
    }

    /// <summary>Clears the identifier cache; used by tests that swap the reader.</summary>
    internal static void ResetCacheForTests() => _cachedMachineId = null;

    private static string? ReadMachineGuidFromRegistry()
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return null;
        }

        try
        {
            using var key = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64)
                                       .OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            return key?.GetValue("MachineGuid")?.ToString();
        }
        catch
        {
            // Silent: a missing GUID becomes a fail-closed error reported by the caller.
            return null;
        }
    }
}
