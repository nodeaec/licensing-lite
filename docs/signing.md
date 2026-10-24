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
# Release (the key comes from outside the repo; scripts/release.ps1 requires it):
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

1. Store `NodeAec.snk` (full, private) **outside any repo**. The current key lives on the
   release machine at `C:\Users\remote\.nodeaec-keys\NodeAec.snk`.
2. Keep a backup copy in a password manager or vault. Losing it means the next release
   gets a new `PublicKeyToken`, a breaking change for every plugin (`docs/rotation.md`).
3. Optional: commit `build/NodeAec.Public.snk` (public only, harmless)
   as a reference/identity — it **signs nothing** (full signing requires
   `DelaySign=false` plus the full key).
4. Releases are built and pushed by hand: `scripts/release.ps1 -Version x.y.z -SnkPath <path>`.
   CI only builds; it never packs or signs, so the key is not stored in GitHub.

> Why `DelaySign=false`: delay signing (`true` plus public key only)
> produces a partially signed assembly that requires `sn -Vr` (skip
> verification) on the test machine — unacceptable for release. Release
> uses full signing with the complete key.
>
> Implementation detail (verified in this repo, SDK 10.0.401): the
> input property is `AssemblyOriginatorKeyFile` — the `ResolveKeySource`
> target resolves it to `KeyOriginatorFile` and **clears** a
> directly-set `KeyOriginatorFile`. Setting the wrong property compiles
> but produces an unsigned build.
>
> `InternalsVisibleTo` + CS1726: a signed assembly requires `PublicKey=`
> on the friend. The `csproj` emits the keyless friend only for unsigned
> builds (local and CI); on signed release the friend is emitted only
> with `-p:NodeAecTestsPublicKey=<hex of the test public key>`. Extract it
> after generating the real key (`sn -Tp assembly.dll`); it is public. Without it, release
> ships without the friend (tests run against unsigned local builds).

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
2. Create an API key scoped to *push* only for the `NodeAec.*` packages, with an expiry.
3. Push by hand with `dotnet nuget push`. Keep the key out of shell history and out of
   the repo (for example, paste it at a prompt or use `dotnet nuget setapikey`).

## 4. Secrets (human summary)

| Secret | Contents | Where |
|---|---|---|
| `NodeAec.snk` | strong-name private key | Release machine + a vault backup, never GitHub |
| nuget.org API key | push scoped to `NodeAec.*` | The publisher only, never GitHub |
| Ed25519 lease private key | signs leases on the server | **server/HSM, never here** |
