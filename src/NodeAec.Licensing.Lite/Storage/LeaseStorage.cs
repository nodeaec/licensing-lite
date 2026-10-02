using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using NodeAec.Licensing.Models;

namespace NodeAec.Licensing.Storage;

/// <summary>
/// Local read of the Master Entitlements Lease (%APPDATA%\NodeAec\entitlements.lease),
/// encrypted via Windows DPAPI (DataProtectionScope.CurrentUser).
/// Read-only: this package never writes, renews, or deletes leases — that is the
/// Node.aec Connector (Hub) role. Without valid DPAPI the content is discarded
/// (returns <c>null</c>), never interpreted as plaintext on Windows.
/// </summary>
public static class LeaseStorage
{
    private static string? _customBasePath;

    /// <summary>
    /// In-memory JWT injected via <c>UseTestLeaseForTests</c> (test-only use).
    /// When non-null, <see cref="LoadMasterLease"/> returns it without touching the file
    /// or DPAPI — SSH-safe path (Session 0 has no user DPAPI). Null = normal
    /// file read. Never used outside tests.
    /// </summary>
    private static string? s_testLeaseOverride;

    /// <summary>
    /// Injects an in-memory JWT as the master lease (test-only use; SSH-safe).
    /// </summary>
    /// <param name="jwt">JWT token returned by <see cref="LoadMasterLease"/>.</param>
    internal static void UseTestLeaseForTests(string? jwt) => s_testLeaseOverride = jwt;

    /// <summary>Removes the injected JWT and restores file reading (test-only use).</summary>
    internal static void ClearTestLeaseOverride() => s_testLeaseOverride = null;

    /// <summary>
    /// Allows injecting an alternate base directory (useful for isolated unit tests).
    /// </summary>
    public static void SetCustomBasePath(string? path)
    {
        _customBasePath = path;
    }

    public static string GetBaseDirectory()
    {
        if (!string.IsNullOrEmpty(_customBasePath))
        {
            if (!Directory.Exists(_customBasePath)) Directory.CreateDirectory(_customBasePath);
            return _customBasePath;
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        var dir = Path.Combine(appData, "NodeAec");
        if (!Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
        }
        return dir;
    }

    public static string GetLeaseFilePath() => Path.Combine(GetBaseDirectory(), "entitlements.lease");

    /// <summary>
    /// Reads and decrypts the local master-lease JWT token.
    /// On Windows, a file that does not decrypt is treated as corrupt/foreign and
    /// discarded (returns <c>null</c>) instead of being accepted as plaintext.
    /// </summary>
    public static string? LoadMasterLease()
    {
        // Test hook (SSH-safe): the in-memory JWT takes precedence over file/DPAPI.
        if (s_testLeaseOverride != null)
        {
            return string.IsNullOrWhiteSpace(s_testLeaseOverride) ? null : s_testLeaseOverride;
        }

        var path = GetLeaseFilePath();
        if (!File.Exists(path)) return null;

        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length == 0) return null;

            if (!TryUnprotect(bytes, out byte[] plain))
            {
                return null;
            }

            return Encoding.UTF8.GetString(plain);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Decodes a JWT payload <b>without</b> verifying the cryptographic signature.
    /// Display use only — license decisions must go through
    /// <c>Gate.Validate</c>, which verifies the Ed25519 signature.
    /// </summary>
    public static MasterLeasePayload? ParseJwtPayload(string token)
    {
        var json = DecodeJwtPayloadJson(token);
        if (json == null) return null;

        try
        {
            return JsonSerializer.Deserialize<MasterLeasePayload>(json);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Returns the payload (middle base64url segment) of a JWT as JSON,
    /// or <c>null</c> when the token is not a usable JWT.
    /// </summary>
    private static string? DecodeJwtPayloadJson(string? token)
    {
        if (string.IsNullOrWhiteSpace(token)) return null;
        var parts = token.Split('.');
        if (parts.Length < 2) return null;

        var base64 = parts[1].Replace('-', '+').Replace('_', '/');
        switch (base64.Length % 4)
        {
            case 2: base64 += "=="; break;
            case 3: base64 += "="; break;
            case 1: return null;
        }

        try
        {
            return Encoding.UTF8.GetString(Convert.FromBase64String(base64));
        }
        catch (FormatException)
        {
            return null;
        }
    }

    /// <summary>
    /// Unprotects written bytes. On Windows, content that does not decrypt is rejected
    /// (<c>false</c>) — never interpreted as plaintext. Off Windows, plaintext
    /// (development/test environment; Revit is Windows-only).
    /// </summary>
    private static bool TryUnprotect(byte[] stored, out byte[] plain)
    {
        if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            plain = stored;
            return true;
        }

        try
        {
            plain = ProtectedData.Unprotect(stored, null, DataProtectionScope.CurrentUser);
            return true;
        }
        catch
        {
            plain = Array.Empty<byte>();
            return false;
        }
    }

    /// <summary>Process lock over atomic writes (see <see cref="WriteAllBytesAtomic"/>).</summary>
    private static readonly object WriteLock = new();

    /// <summary>
    /// Writes bytes atomically: writes to a uniquely named temp file
    /// (<c>{path}.{guid}.tmp</c>) in the same directory and promotes it to the target
    /// (<c>File.Replace</c> when it already exists; <c>File.Move</c> on first write),
    /// always under <see cref="WriteLock"/>. Uses only APIs present on both
    /// .NET Framework 4.8 and .NET 8/10.
    /// Test/tooling utility; the production gate is read-only.
    /// </summary>
    /// <param name="path">Target file.</param>
    /// <param name="bytes">Content to write.</param>
    public static void WriteAllBytesAtomic(string path, byte[] bytes)
    {
        var dir = Path.GetDirectoryName(path);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir)) Directory.CreateDirectory(dir);

        string tmp = $"{path}.{Guid.NewGuid():N}.tmp";
        try
        {
            lock (WriteLock)
            {
                File.WriteAllBytes(tmp, bytes);

                if (File.Exists(path))
                {
                    try
                    {
                        File.Replace(tmp, path, null);
                    }
                    catch (PlatformNotSupportedException)
                    {
                        // File.Replace is missing on FAT32/exFAT and some shares:
                        // delete + move under WriteLock.
                        File.Delete(path);
                        File.Move(tmp, path);
                    }
                }
                else
                {
                    File.Move(tmp, path);
                }
            }
        }
        finally
        {
            try
            {
                if (File.Exists(tmp)) File.Delete(tmp);
            }
            catch
            {
            }
        }
    }
}
