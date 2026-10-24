<#
.SYNOPSIS
  Packs NodeAec.Licensing.Lite (.nupkg) + SHA256 checksum for a release.

.DESCRIPTION
  Mirrors revit-connector/scripts/release.ps1 conventions: artifacts land in
  release/ with a "<hash>  <filename>" .sha256 sidecar (same format as
  Get-FileHash output). Re-run AFTER Authenticode signing — signing changes
  the bytes, so the checksum must always be generated last
  (see docs/signing.md §2: build -> strong-name -> Authenticode -> sha256).

.EXAMPLE
  $env:NODEAEC_SNK_PATH = "C:\secure\NodeAec.snk"
  powershell -ExecutionPolicy Bypass -File scripts/release.ps1 -Version 0.2.0

  -Version has no default, and the strong-name key is mandatory: a release
  package must never ship unsigned (see docs/signing.md section 1). Unsigned
  builds also carry a keyless InternalsVisibleTo, which would let any assembly
  named NodeAec.Licensing.Lite.Tests reach the test-only anchor hook.
#>
param(
  [string]$Version,
  [string]$Configuration = "Release",
  [string]$SnkPath = $env:NODEAEC_SNK_PATH
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($Version)) {
  throw "-Version is required (e.g. -Version 0.2.0)."
}
if ([string]::IsNullOrWhiteSpace($SnkPath) -or -not (Test-Path $SnkPath)) {
  throw "Strong-name key not found. Pass -SnkPath <file.snk> or set NODEAEC_SNK_PATH. Release packages must be signed (docs/signing.md section 1)."
}

$RepoRoot = Split-Path $PSScriptRoot -Parent
$Project = Join-Path $RepoRoot "src\NodeAec.Licensing.Lite\NodeAec.Licensing.Lite.csproj"
$ReleaseDir = Join-Path $RepoRoot "release"

Write-Host "==> dotnet pack $Project -c $Configuration -p:Version=$Version"
& dotnet pack $Project -c $Configuration -p:Version=$Version -p:NodeAecSnkPath=$SnkPath --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed ($LASTEXITCODE)" }

$nupkg = Get-ChildItem (Join-Path $RepoRoot "src\NodeAec.Licensing.Lite\bin\$Configuration") `
  -Filter "NodeAec.Licensing.Lite.$Version.nupkg" -Recurse |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $nupkg) { throw "nupkg for version $Version not found under bin\$Configuration" }

# Verify the signature actually landed: every packed DLL must carry a PublicKeyToken.
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::OpenRead($nupkg.FullName)
try {
  $dlls = $zip.Entries | Where-Object { $_.FullName -like "lib/*/NodeAec.Licensing.Lite.dll" }
  if (-not $dlls) { throw "No NodeAec.Licensing.Lite.dll found inside $($nupkg.Name)." }
  foreach ($entry in $dlls) {
    $tmp = Join-Path ([System.IO.Path]::GetTempPath()) ([System.IO.Path]::GetRandomFileName() + ".dll")
    [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $tmp, $true)
    try {
      $token = [Reflection.AssemblyName]::GetAssemblyName($tmp).GetPublicKeyToken()
      if (-not $token -or $token.Length -eq 0) { throw "$($entry.FullName) is not strong-named." }
    } finally {
      Remove-Item $tmp -Force -ErrorAction SilentlyContinue
    }
  }
} finally {
  $zip.Dispose()
}

New-Item $ReleaseDir -ItemType Directory -Force | Out-Null
Copy-Item $nupkg.FullName (Join-Path $ReleaseDir $nupkg.Name) -Force
$staged = Join-Path $ReleaseDir $nupkg.Name

# Checksum LAST (after any Authenticode signing — re-run this script then).
$hash = (Get-FileHash $staged -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $($nupkg.Name)" | Out-File "$staged.sha256" -Encoding ascii
Write-Host "==> release: $staged"
Write-Host "    sha256: $hash"
