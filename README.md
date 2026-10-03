# NodeAec.Licensing.Lite

Offline license gate for Node.aec Revit add-ins. This NuGet package evaluates a locally stored, signed entitlements lease and returns an immutable verdict. It performs no HTTP requests, hosts no UI, and starts no background threads or timers. Lease synchronization is owned exclusively by the Node.aec Connector (Hub); this library is read-and-verify only.

All failure modes are fail-closed: a missing lease, an invalid signature, a machine mismatch, or an expired offline grace period yields `IsLicensed = false` with a PT-BR `Message` intended to be displayed verbatim.

## Installation

Install the NuGet package once per add-in project:

```powershell
dotnet add package NodeAec.Licensing.Lite
```

or declare the dependency directly:

```xml
<PackageReference Include="NodeAec.Licensing.Lite" Version="1.0.0-preview.1" />
```

## Usage (3 lines)

Call the gate as the first statement of `IExternalCommand.Execute` and honor the verdict:

```csharp
using NodeAec.Licensing;

const string ProductSlug = "my-plugin";

var gate = Gate.Validate(ProductSlug);
if (!gate.IsLicensed)
{
    TaskDialog.Show("License Required", gate.Message); // verbatim, already user guidance
    Gate.OpenConnector();                              // silent no-op if Hub is absent
    return Result.Cancelled;
}
```

`Gate.Validate` never throws. `Gate.OpenConnector` forwards to the Connector Hub window via reflection when the Hub is loaded in the same `AppDomain`, and is a silent no-op otherwise.

The public API lives in the `NodeAec.Licensing` namespace — stable across preview versions — so consuming the package needs only a `using` directive.

## Snapshot (6 members)

`Gate.Validate` returns an immutable `Snapshot`. `IsLicensed` is the only branch point.

| Member | Type | Meaning |
|---|---|---|
| `IsLicensed` | `bool` | `true` only for an active, verified grant. |
| `Message` | `string` | PT-BR guidance text. Display verbatim on denial. |
| `ProductName` | `string?` | Display name of the grant; `null` on denial. |
| `LicenseType` | `string?` | Grant type (for example `perpetual`); `null` on denial. |
| `LicenseKey` | `string?` | License key; `null` on denial. |
| `ExpiresAt` | `DateTimeOffset?` | Grant expiry; `null` means no expiry claim (perpetual). |

## How it works

1. Reads `%APPDATA%\NodeAec\entitlements.lease`, protected with DPAPI `CurrentUser` (`DataProtectionScope.CurrentUser`). Content that does not decrypt is discarded, never treated as plaintext.
2. Verifies the JWT Ed25519/EdDSA signature (RFC 8032, `alg: EdDSA`) against the compiled `TrustedAnchors` (SPKI public keys). The anchor list supports rotation as N/N+1: during a rotation it holds the replacement key and the key being phased out at the same time, so installed plugins keep verifying; once the transition completes, the list holds the replacement key only. No private key exists in this repository.
3. Evaluates claims only after the signature verifies, in fixed order: `iss` → `scope` → `aud` → `iat` (5-minute future tolerance) → machine binding (`mid`, SHA-256 of the Windows `MachineGuid`) → `exp` (offline grace deadline; missing or implausible `exp` is treated as expired) → product `slug` present and active (`status`, `granted`, per-grant expiry).

## Target frameworks

| TFM | Revit host |
|---|---|
| `net48` | Revit 2023 / 2024 |
| `net8.0-windows` | Revit 2025 / 2026 |
| `net10.0-windows` | Revit 2027 |

Ed25519 verification is managed code (BouncyCastle, no native dependencies). `System.Text.Json` and DPAPI are referenced via `PackageReference` per TFM so `net48` builds resolve them explicitly while `net8.0-windows` / `net10.0-windows` rely on the in-box runtime inside Revit.

## Design constraints

- No HTTP, no login UI, no background work. The only UI in the usage pattern is the caller-owned `TaskDialog` showing `Snapshot.Message`.
- Fail-closed at every layer: `Gate.Validate` catches all exceptions and returns a denied `Snapshot`; an unusable anchor set denies rather than skips verification.
- Write path belongs to the Connector Hub. This package never writes, renews, or deletes the lease file in production.

## Signing and rotation

- Strong-name (`.snk`) and Authenticode (Azure Trusted Signing) procedure: `docs/signing.md`.
- Ed25519 anchor rotation (N/N+1) and strong-name key change: `docs/rotation.md`.

Release order is `build → strong-name → Authenticode → sha256`; `scripts/release.ps1` regenerates the `.sha256` sidecar last because signing changes the bytes.
