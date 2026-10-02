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
  powershell -ExecutionPolicy Bypass -File scripts/release.ps1 -Version 1.0.0-preview.1
#>
param(
  [string]$Version = "1.0.0-preview.1",
  [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Split-Path $PSScriptRoot -Parent
$Project = Join-Path $RepoRoot "src\NodeAec.Licensing.Lite\NodeAec.Licensing.Lite.csproj"
$ReleaseDir = Join-Path $RepoRoot "release"

Write-Host "==> dotnet pack $Project -c $Configuration -p:Version=$Version"
& dotnet pack $Project -c $Configuration -p:Version=$Version --nologo
if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed ($LASTEXITCODE)" }

$nupkg = Get-ChildItem (Join-Path $RepoRoot "src\NodeAec.Licensing.Lite\bin\$Configuration") `
  -Filter "NodeAec.Licensing.Lite.$Version.nupkg" -Recurse |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $nupkg) { throw "nupkg for version $Version not found under bin\$Configuration" }

New-Item $ReleaseDir -ItemType Directory -Force | Out-Null
Copy-Item $nupkg.FullName (Join-Path $ReleaseDir $nupkg.Name) -Force
$staged = Join-Path $ReleaseDir $nupkg.Name

# Checksum LAST (after any Authenticode signing — re-run this script then).
$hash = (Get-FileHash $staged -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  $($nupkg.Name)" | Out-File "$staged.sha256" -Encoding ascii
Write-Host "==> release: $staged"
Write-Host "    sha256: $hash"
