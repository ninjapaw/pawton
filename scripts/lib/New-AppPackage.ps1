<#
.SYNOPSIS
    Creates a deployment zip whose entry names use forward slashes.

.DESCRIPTION
    Windows PowerShell 5.1's Compress-Archive writes directory separators as
    backslashes, which violates the ZIP specification (APPNOTE 4.4.17.1 requires
    '/'). Linux-side extractors such as App Service's Kudu/Oryx therefore treat
    "src\lib\adminDb.mjs" as one flat file name instead of a nested path, so the
    application source tree arrives flattened and the remote build produces an
    unusable site.

    This script writes entries explicitly with forward slashes so the package
    extracts correctly on Linux.

.PARAMETER SourcePath
    Directory whose contents become the archive root.

.PARAMETER DestinationPath
    Zip file to create. Overwritten when it already exists.

.PARAMETER Exclude
    Top-level directory names to skip, matching the 'zip -x node_modules/*'
    behaviour used when the zip binary is available.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SourcePath,
    [Parameter(Mandatory = $true)][string]$DestinationPath,
    [string[]]$Exclude = @()
)

$ErrorActionPreference = 'Stop'

$root = (Resolve-Path -LiteralPath $SourcePath).ProviderPath.TrimEnd('\', '/')
if (-not (Test-Path -LiteralPath $root -PathType Container)) {
    throw "SourcePath '$SourcePath' is not a directory."
}

$destDir = Split-Path -Parent $DestinationPath
if ($destDir -and -not (Test-Path -LiteralPath $destDir)) {
    New-Item -ItemType Directory -Path $destDir -Force | Out-Null
}
if (Test-Path -LiteralPath $DestinationPath) {
    Remove-Item -LiteralPath $DestinationPath -Force
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$excludedRoots = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
# powershell.exe -File passes "a,b,c" through as a single argument, so split on
# commas to accept both that form and a native PowerShell array.
foreach ($name in ($Exclude -split ',')) {
    $trimmed = $name.Trim()
    if ($trimmed) { [void]$excludedRoots.Add($trimmed) }
}

$archive = [System.IO.Compression.ZipFile]::Open($DestinationPath, [System.IO.Compression.ZipArchiveMode]::Create)
try {
    $written = 0
    # Enumerate top-level entries first and skip excluded directories before
    # recursing, so large trees such as node_modules are never walked.
    foreach ($top in Get-ChildItem -LiteralPath $root -Force) {
        if ($excludedRoots.Contains($top.Name)) { continue }

        $files = if ($top.PSIsContainer) {
            Get-ChildItem -LiteralPath $top.FullName -Recurse -File -Force
        } else {
            @($top)
        }

        foreach ($file in $files) {
            $relative = $file.FullName.Substring($root.Length).TrimStart('\', '/')
            # Normalise to the separator the ZIP specification mandates.
            $entryName = $relative -replace '\\', '/'

            $entry = $archive.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Optimal)
            $entryStream = $entry.Open()
            try {
                $fileStream = [System.IO.File]::OpenRead($file.FullName)
                try { $fileStream.CopyTo($entryStream) } finally { $fileStream.Dispose() }
            } finally {
                $entryStream.Dispose()
            }
            $written++
        }
    }
} finally {
    $archive.Dispose()
}

if ($written -eq 0) {
    throw "No files were added to '$DestinationPath' from '$root'."
}

Write-Output "Packaged $written file(s) into $DestinationPath"
