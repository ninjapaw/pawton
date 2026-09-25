<#
.SYNOPSIS
Builds a canary-only App Service zip without portal code, dependencies or secrets.
.DESCRIPTION
Audit lists the two allowlisted source files without writing anything. Apply creates
a new archive and refuses to overwrite an existing artifact.
#>
[CmdletBinding()]
param(
    [switch]$Audit,
    [string]$OutputPath
)
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$files = @(
    'scripts/serve-external-source-canary.mjs',
    'apps/pawton-manufacturing/src/lib/externalSourceProbe.mjs'
)
foreach ($file in $files) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $file) -PathType Leaf)) {
        throw "Required canary source is missing: $file"
    }
}
if ($Audit) {
    [pscustomobject]@{ Mode = 'audit'; Writes = $false; Files = $files } | ConvertTo-Json
    return
}
if (-not $OutputPath) { $OutputPath = Join-Path $root 'output/sql-canary.zip' }
$OutputPath = [IO.Path]::GetFullPath($OutputPath)
if (Test-Path -LiteralPath $OutputPath) { throw 'Archive already exists. Choose a new OutputPath; nothing was overwritten.' }
$parent = Split-Path $OutputPath -Parent
$null = New-Item -ItemType Directory -Path $parent -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$stream = [IO.File]::Open($OutputPath, [IO.FileMode]::CreateNew)
$archive = $null
try {
    $archive = [IO.Compression.ZipArchive]::new($stream, [IO.Compression.ZipArchiveMode]::Create, $true)
    foreach ($file in $files) {
        $null = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, (Join-Path $root $file), $file, [IO.Compression.CompressionLevel]::Optimal)
    }
} finally {
    if ($archive) { $archive.Dispose() }
    $stream.Dispose()
}
$hasher = [Security.Cryptography.SHA256]::Create()
$inputStream = [IO.File]::OpenRead($OutputPath)
try {
    $digest = [BitConverter]::ToString($hasher.ComputeHash($inputStream)).Replace('-', '')
} finally {
    $inputStream.Dispose()
    $hasher.Dispose()
}
[pscustomobject]@{ Mode = 'packaged'; Path = $OutputPath; Sha256 = $digest; Files = $files } | ConvertTo-Json