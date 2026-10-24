# Signing: strong-name (.snk)

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

Current release key: `PublicKeyToken=b00754dbadfd618b` (first used in 0.2.0; 0.1.0 was unsigned).

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

## 2. Authenticode — not used

The package does not carry an Authenticode signature, by decision. What it has instead:

- The strong name (§1) gives the .NET identity, and `release.ps1` refuses to pack an unsigned build.
- nuget.org adds its repository signature (`.signature.p7s`) to every `.nupkg` on upload.
- `release/*.sha256` is the checksum of the exact package that was pushed.

Revit only checks Authenticode on the add-in's main assembly (the one named in the
`.addin`), never on dependencies such as this package, so signing it would not change
what the user sees. Partner plugins sign, or don't sign, their own main assembly.

`scripts/release.ps1` refuses to run without `-Version` and a strong-name key
(`-SnkPath` or `NODEAEC_SNK_PATH`), and fails if any packed DLL lacks a
`PublicKeyToken`. Why: an unsigned build emits a keyless
`InternalsVisibleTo("NodeAec.Licensing.Lite.Tests")`, so any assembly with that name
could call the test-only anchor hook. Version 0.1.0 on NuGet.org was published
unsigned and has this friend declaration; 0.2.0 is its signed successor.

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
| Ed25519 lease private key | signs leases on the server | **server/HSM, never here** |
