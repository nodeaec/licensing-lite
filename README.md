# NodeAec.Licensing.Lite

Offline license gate for Node.aec Revit add-ins. This NuGet package evaluates a locally stored, signed entitlements lease and returns an immutable verdict. It performs no HTTP requests, hosts no UI, and starts no background threads or timers. Lease synchronization is owned exclusively by the Node.aec Connector (Hub); this library is read-and-verify only.

All failure modes are fail-closed: a missing lease, an invalid signature, a machine mismatch, or an expired offline grace period yields `IsLicensed = false`, a `Reason` naming the case, and a message (Portuguese or English) intended to be displayed verbatim.

## Guides

| You are… | Read |
|---|---|
| Starting a new plugin | [Template](https://github.com/nodeaec/templates-revit#readme): `dotnet new nodeaec-revit-plugin` generates the integration |
| Adding licensing to an existing plugin | [Partner Integration Guide](https://github.com/nodeaec/revit-connector/blob/main/docs/PARTNER_INTEGRATION.md) |
| Learning from a working example | [Sample Plugin](https://github.com/nodeaec/revit-sample-plugin#readme) |
| A coding agent doing any of these | [`licensing-integrate` skill](https://github.com/nodeaec/revit-sample-plugin/tree/main/.agents/skills/licensing-integrate) |

This README is the package reference: API, reasons and messages, and how verification works.

## Installation

Install the NuGet package once per add-in project:

```powershell
dotnet add package NodeAec.Licensing.Lite
```

or declare the dependency directly:

```xml
<PackageReference Include="NodeAec.Licensing.Lite" Version="0.3.0" />
```

## Usage (3 lines)

Call the gate as the first statement of `IExternalCommand.Execute` and honor the verdict:

```csharp
using NodeAec.Licensing;

const string ProductSlug = "my-plugin";

var gate = Gate.Validate(ProductSlug);
if (!gate.IsLicensed)
{
    // Verbatim, already user guidance. gate.Message is the Portuguese text.
    TaskDialog.Show("License Required", gate.GetMessage(MessageLanguage.English));
    Gate.OpenConnector(); // silent no-op if Hub is absent
    return Result.Cancelled;
}
```

`Gate.Validate` never throws. `Gate.OpenConnector` forwards to the Connector Hub window via reflection when the Hub is loaded in the same `AppDomain`, and is a silent no-op otherwise.

The public API lives in the `NodeAec.Licensing` namespace — stable across preview versions — so consuming the package needs only a `using` directive.

## Snapshot

`Gate.Validate` returns an immutable `Snapshot`. `IsLicensed` is the only branch point.

| Member | Type | Meaning |
|---|---|---|
| `IsLicensed` | `bool` | `true` only for an active, verified grant. |
| `Reason` | `GateReason` | Why: `Licensed`, or the one failure case (table below). For logs and UI tweaks, never to decide whether to run. Since 0.3.0. |
| `GetMessage(MessageLanguage)` | `string` | End-user text in `Portuguese` or `English`. Display verbatim on denial. Since 0.3.0. |
| `Message` | `string` | Same as `GetMessage(MessageLanguage.Portuguese)`. |
| `ProductName` | `string?` | Display name of the grant; `null` on denial. |
| `LicenseType` | `string?` | Grant type (for example `perpetual`); `null` on denial. |
| `LicenseKey` | `string?` | The end user's license key; `null` on denial. Never log it or send it anywhere. |
| `ExpiresAt` | `DateTimeOffset?` | Grant expiry; `null` means no expiry claim (perpetual). |

## Reasons and messages

Each `GateReason` value has a fixed number that never changes or gets reused. New values may
be added later, so a `switch` over `GateReason` needs a `default` branch. Dates are
`dd/MM/yyyy` in Portuguese and `MMM d, yyyy` in English, the same on every Windows locale.

| # | `GateReason` | English | Portuguese |
|---|---|---|---|
| 0 | `Licensed` | License active and verified. | Licença ativa e verificada. |
| 1 | `MissingProductSlug` | No product slug was given for validation. | Slug do produto não informado para validação. |
| 2 | `NoLease` | No Node.aec credentials were found on this computer. Open the Node.aec Connector on the Ribbon to sign in or activate your license. | Nenhuma credencial do Node.aec encontrada nesta estação. Abra o Node.aec Connector na Ribbon para entrar com sua conta ou ativar sua licença. |
| 3 | `CorruptLease` | The local license is corrupted or invalid. Open the Node.aec Connector to synchronize again. | Concessão corrompida ou estrutura inválida. Abra o Node.aec Connector para ressincronizar. |
| 4 | `SignatureInvalid` | The local license failed the security check. Connect to the internet and click refresh in the Node.aec Connector. | A licença local não passou na verificação de segurança. Conecte-se à internet e clique em atualizar no Node.aec Connector. |
| 5 | `UnknownIssuer` | The local license comes from an unknown issuer. Connect to the internet and click refresh in the Node.aec Connector. | Origem da licença local desconhecida. Conecte-se à internet e clique em atualizar no Node.aec Connector. |
| 6 | `UnsupportedFormat` | The local license is in an unsupported format. Connect to the internet and click refresh in the Node.aec Connector. | A licença local está em formato não suportado. Conecte-se à internet e clique em atualizar no Node.aec Connector. |
| 7 | `WrongAudience` | The local license was not issued for this add-in. Connect to the internet and click refresh in the Node.aec Connector. | A licença local não foi emitida para este add-in. Conecte-se à internet e clique em atualizar no Node.aec Connector. |
| 8 | `ClockInvalid` | The local license date is invalid. Check this computer's date and time and try again. | A data da licença local é inválida. Confira a data e hora deste computador e tente novamente. |
| 9 | `MachineIdUnavailable` | This computer could not be identified (Windows MachineGuid unavailable). Contact Node.aec support. | Não foi possível identificar esta máquina (MachineGuid do Windows indisponível). Contate o suporte Node.aec. |
| 10 | `MachineMismatch` | The licenses were issued for another computer (Hardware ID mismatch). | A concessão de licenças foi emitida para outra estação de trabalho (Hardware ID divergente). |
| 11 | `OfflineGraceExpired` | The offline grace period expired on {date}. Connect to the internet to synchronize. | O prazo de tolerância offline expirou em {date}. Conecte-se à internet para sincronizar. |
| 12 | `LeaseExpiryUnreadable` | The local license deadline could not be read. Connect to the internet and click refresh in the Node.aec Connector. | O prazo da licença local não pôde ser lido. Conecte-se à internet e clique em atualizar no Node.aec Connector. |
| 13 | `ProductNotFound` | The product '{slug}' is not among this account's active licenses. Buy or activate it in the Node.aec catalog. | O produto '{slug}' não consta nas licenças ativas desta conta. Adquira ou ative no catálogo Node.aec. |
| 14 | `SeatLimitReached` | All computers allowed for '{name}' are already in use. | O limite de computadores simultâneos para '{name}' foi atingido. |
| 15 | `LicenseExpired` | The license or trial of '{name}' expired on {date}. | A licença ou período de teste de '{name}' expirou em {date}. |
| 16 | `LicenseInactive` | The license of '{name}' has status '{status}'. | A licença de '{name}' está com status '{status}'. |
| 17 | `VerificationError` | The local license could not be verified. Open the Node.aec Connector to synchronize again. | Não foi possível verificar a licença local. Abra o Node.aec Connector para ressincronizar. |

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

- No HTTP, no login UI, no background work. The only UI in the usage pattern is the caller-owned `TaskDialog` showing the snapshot's message.
- Fail-closed at every layer: `Gate.Validate` catches all exceptions and returns a denied `Snapshot`; an unusable anchor set denies rather than skips verification.
- Write path belongs to the Connector Hub. This package never writes, renews, or deletes the lease file in production.

## Compatibility between versions

The Node.aec Connector references this package too, and so does every partner plugin, so
several copies can meet in one Revit process. On Revit 2025+ (.NET 8/10) only one version
loads: the first one. Two rules keep that safe:

- **Additive only.** A release never removes or changes a public member, so a plugin built
  against an older version works with any newer one.
- **The Connector ships the newest version.** It loads the package at startup, so plugins built
  against the same or an older version always find what they need.

Details: [revit-connector `docs/lite-adoption.md`](https://github.com/nodeaec/revit-connector/blob/main/docs/lite-adoption.md).

## Signing and rotation

- Strong-name (`.snk`) procedure, and why there is no Authenticode: `docs/signing.md`.
- Ed25519 anchor rotation (N/N+1) and strong-name key change: `docs/rotation.md`.

`scripts/release.ps1` builds with the strong-name key, packs, and writes the `.sha256` sidecar last. It requires `-Version` and a strong-name key (`-SnkPath` or `NODEAEC_SNK_PATH`), and fails if any packed DLL is not strong-named: an unsigned build carries a keyless `InternalsVisibleTo` for the test assembly and must never be published.
