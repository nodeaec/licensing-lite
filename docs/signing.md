# Signing: strong-name (.snk) + Authenticode (Trusted Signing)

> Golden rule: **no private key enters git.** If one leaks, rotate the
> key and follow `docs/rotation.md`.

## 1. Strong-name (.snk) — proves assembly *identity*

What it is: the strong name binds the assembly identity
(`AssemblyName` + `Version` + `PublicKeyToken`). The plugin project
references the `NodeAec.Licensing.Lite` NuGet package via `PackageReference`
with the expected token, so the CLR only binds the assembly signed
with the Node.aec key — a DLL with the same name and type but without
the matching signature is not bound in its place.

The `csproj` signs **only when a key is supplied** — a local build without
a key stays green and unsigned:

```powershell
# CI / release (the key comes from the secret, never from the repo):
dotnet build -p:NodeAecSnkPath=C:\tmp\NodeAec.snk
# or via the environment:
$env:NODEAEC_SNK_PATH = "C:\tmp\NodeAec.snk"; dotnet build
```

### Generate the REAL key (human step, once, on Windows)

```powershell
# sn.exe ships with Visual Studio / Windows SDK:
sn.exe -k NodeAec.snk          # 2048-bit pair (keep this file safe!)
sn.exe -p NodeAec.snk NodeAec.Public.snk   # extracts the public part only
sn.exe -T NodeAec.Licensing.Lite.dll       # verifies the PublicKeyToken
```

1. Store `NodeAec.snk` (full, private) **outside any repo**.
2. Convert it to base64 and save it as a GitHub secret
   (repo Settings > Secrets > Actions):
   `NODEAEC_SNK_BASE64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes("NodeAec.snk"))`.
3. Optional: commit `build/NodeAec.Public.snk` (public only, harmless)
   as a reference/identity — it **signs nothing** (full signing requires
   `DelaySign=false` plus the full key, which exists only in CI).
4. CI (`ci.yml`, `release` job) decodes the secret to a temporary
   runner file and passes `-p:NodeAecSnkPath=` — the `.snk` never
   appears in logs or artifacts.

> Why `DelaySign=false`: delay signing (`true` plus public key only)
> produces a partially signed assembly that requires `sn -Vr` (skip
> verification) on the test machine — unacceptable for release. Release
> uses full signing in CI with the complete key from the secret.
>
> Implementation detail (verified in this repo, SDK 10.0.401): the
> input property is `AssemblyOriginatorKeyFile` — the `ResolveKeySource`
> target resolves it to `KeyOriginatorFile` and **clears** a
> directly-set `KeyOriginatorFile`. Setting the wrong property compiles
> but produces an unsigned build.
>
> `InternalsVisibleTo` + CS1726: a signed assembly requires `PublicKey=`
> on the friend. The `csproj` emits the keyless friend only for unsigned
> builds (local/test CI); on signed release the friend is emitted only
> with `-p:NodeAecTestsPublicKey=<hex of the test public key>`. Extract it
> after generating the real key (`sn -Tp assembly.dll`) and store it as a
> CI variable (not a secret — it is public). Without it, release ships
> without the friend (tests still run in the unsigned job).

### Verify the token (any DLL)

```powershell
# PublicKeyToken via reflection (VersionInfo does NOT show the token):
$dll = "src\NodeAec.Licensing.Lite\bin\Release\net8.0-windows\NodeAec.Licensing.Lite.dll"
[BitConverter]::ToString(
  [Reflection.AssemblyName]::GetAssemblyName((Resolve-Path $dll)).GetPublicKeyToken()
).Replace("-","").ToLowerInvariant()
```

## 2. Authenticode (Trusted Signing) — proves *authorship* on Windows

What it is: Windows/SmartScreen checks *who* signed the DLL and the `.nupkg`
(strong naming proves .NET identity; Authenticode proves publisher plus
guarantees the file has not been altered). Requires an **Azure Trusted Signing**
account.

Release flow (on Windows, after `scripts/release.ps1` produces the `.nupkg`):

```powershell
# 1. Install the Trusted Signing SDK (once):
dotnet tool install --global Azure.CodeSigning.DotNetTool  # or via AKV + signtool

# 2. Sign the DLLs (one per TFM) + package, with timestamp:
$files = @(
  "src\NodeAec.Licensing.Lite\bin\Release\net48\NodeAec.Licensing.Lite.dll",
  "src\NodeAec.Licensing.Lite\bin\Release\net8.0-windows\NodeAec.Licensing.Lite.dll",
  "src\NodeAec.Licensing.Lite\bin\Release\net10.0-windows\NodeAec.Licensing.Lite.dll",
  "release\NodeAec.Licensing.Lite.1.0.0-preview.1.nupkg"
)
# Via Trusted Signing (account/config from TRUSTED_SIGNING_* secrets):
#   AzureTrustedSigning.exe sign -f $files `
#     -a <account> -p <profile> -e <endpoint> -t <tenant>
# Classic alternative (EV cert on HSM) — always with an RFC 3161 timestamp:
#   signtool.exe sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
#     /a <each file>

# 3. Verify:
signtool.exe verify /pa <each file>

# 4. Regenerate the checksum AFTER signing (signing changes the bytes!):
Get-FileHash release\*.nupkg -Algorithm SHA256
```

Required order: **build → strong-name → Authenticode → sha256**.
`scripts/release.ps1` performs build+pack+sha256; Authenticode signing
goes between pack and the final hash (the script regenerates the `.sha256`
on its own with every run — run it again after signing).

## 3. NuGet.org — prefix reservation (human step)

Before the first `dotnet nuget push`:

1. On the Node.aec org account at nuget.org > **Reserve prefix** >
   prefix `NodeAec.*`. Without this, any account can publish `NodeAec.*`.
2. Create an API key scoped to *push* only for `NodeAec.Licensing.Lite`,
   and store it as the `NUGET_API_KEY` secret (push is manual — see Wave 4).
3. Never run `dotnet nuget push` from a dev machine with the key in shell
   history; push only via an assisted release tag.

## 4. Secrets (human summary)

| Secret | Contents | Where |
|---|---|---|
| `NODEAEC_SNK_BASE64` | full `.snk` as base64 | GitHub Secrets |
| `NUGET_API_KEY` | push scoped to the package | GitHub Secrets |
| `TRUSTED_SIGNING_*` | account/profile/endpoint/tenant | GitHub Secrets |
| Ed25519 lease private key | signs leases on the server | **server/HSM, never here** |
