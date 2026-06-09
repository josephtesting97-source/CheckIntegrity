<# 
.SYNOPSIS
Checks files or folders for files that look unreadable, truncated, malformed, or suspicious.

.DESCRIPTION
This tool never modifies the files it scans. It performs lightweight checks for all
files, then deeper validation for common formats such as ZIP/Office documents,
PDF, JSON, XML, images, gzip, and SQLite databases.

.\Check-CorruptFiles.ps1 -Path "C:\Users\you\Documents" -ReportPath ".\file-check-report.csv"

.EXAMPLE
.\Check-CorruptFiles.ps1 -Path "D:\Photos" -JsonPath ".\photo-check-report.json" -IncludeHashes

.EXAMPLE
.\Check-CorruptFiles.ps1 -Path "C:\Important\a.docx","C:\Important\b.xlsx" -ReportPath ".\important-report.csv"
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateNotNullOrEmpty()]
    [string[]]$Path = @("."),

    [string]$ReportPath,

    [string]$JsonPath,

    [switch]$IncludeHashes,

    [switch]$NoRecurse,

    [switch]$IncludeHidden,

    [string[]]$Extensions,

    [int]$MaxDeepCheckMB = 512,

    [int]$MaxHashMB = 2048
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

try {
    Add-Type -AssemblyName System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
} catch {
    # Windows PowerShell can already have the compression types loaded.
}

$inputPaths = @($Path | ForEach-Object {
    $_ -split ","
} | ForEach-Object {
    $_.Trim()
} | Where-Object {
    $_
})

$resolvedItems = @($inputPaths | ForEach-Object {
    $inputPath = $_
    Resolve-Path -LiteralPath $inputPath | ForEach-Object {
        Get-Item -LiteralPath $_.Path -Force
    }
})

if ($resolvedItems.Count -eq 0) {
    throw "No files or folders matched the provided path."
}

$relativeBasePath = if ($resolvedItems.Count -eq 1) {
    if ($resolvedItems[0].PSIsContainer) {
        $resolvedItems[0].FullName
    } else {
        $resolvedItems[0].DirectoryName
    }
} else {
    (Get-Location).Path
}

$scanLabel = if ($resolvedItems.Count -eq 1) {
    $resolvedItems[0].FullName
} else {
    "$($resolvedItems.Count) input path(s)"
}

$maxDeepCheckBytes = [int64]$MaxDeepCheckMB * 1MB
$maxHashBytes = [int64]$MaxHashMB * 1MB

$normalizedExtensions = @()

if ($Extensions) {
    $normalizedExtensions = @($Extensions | ForEach-Object {
        $_ -split ","
    } | ForEach-Object {
        $ext = $_.Trim().ToLowerInvariant()
        if ($ext -and -not $ext.StartsWith(".")) {
            ".$ext"
        } else {
            $ext
        }
    } | Where-Object {
        $_
    } | Select-Object -Unique)
}

function Resolve-RelativePath {
    param(
        [string]$BasePath,
        [string]$TargetPath
    )

    $baseUri = [System.Uri]::new(($BasePath.TrimEnd("\") + "\"))
    $targetUri = [System.Uri]::new($TargetPath)

    [System.Uri]::UnescapeDataString(
        $baseUri.MakeRelativeUri($targetUri).ToString()
    ).Replace("/", "\")
}

function Join-Issue {
    param([string[]]$Issues)

    ($Issues | Where-Object { $_ }) -join "; "
}

function New-CheckResult {
    param(
        [System.IO.FileInfo]$File,
        [string]$Status,
        [int]$Severity,
        [string]$Reason,
        [string]$Details,
        [string]$Sha256
    )

    [pscustomobject]@{
        Status        = $Status
        Severity      = $Severity
        Path          = $File.FullName
        RelativePath  = Resolve-RelativePath -BasePath $relativeBasePath -TargetPath $File.FullName
        Extension     = $File.Extension.ToLowerInvariant()
        SizeBytes     = $File.Length
        LastWriteTime = $File.LastWriteTime
        Reason        = $Reason
        Details       = $Details
        SHA256        = $Sha256
    }
}

function Read-HeaderBytes {
    param(
        [string]$FilePath,
        [int]$Count
    )

    $buffer = New-Object byte[] $Count

    $stream = [System.IO.File]::Open(
        $FilePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    )

    try {
        $read = $stream.Read($buffer, 0, $buffer.Length)

        if ($read -lt $Count) {
            $short = New-Object byte[] $read
            [Array]::Copy($buffer, $short, $read)
            return $short
        }

        return $buffer
    }
    finally {
        $stream.Dispose()
    }
}

function Read-TailBytes {
    param(
        [string]$FilePath,
        [int64]$FileLength,
        [int]$Count
    )

    $readCount = [Math]::Min($Count, [int]$FileLength)
    $buffer = New-Object byte[] $readCount

    $stream = [System.IO.File]::Open(
        $FilePath,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    )

    try {
        [void]$stream.Seek(-1 * $readCount, [System.IO.SeekOrigin]::End)
        [void]$stream.Read($buffer, 0, $buffer.Length)
        return $buffer
    }
    finally {
        $stream.Dispose()
    }
}

function Get-Sha256 {
    param([System.IO.FileInfo]$File)

    if ($File.Length -gt $maxHashBytes) {
        return "SKIPPED_OVER_${MaxHashMB}MB"
    }

    $sha = [System.Security.Cryptography.SHA256]::Create()

    $stream = [System.IO.File]::Open(
        $File.FullName,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
    )

    try {
        $hash = $sha.ComputeHash($stream)
        return ([BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    }
    finally {
        $stream.Dispose()
        $sha.Dispose()
    }
}

function Test-ZipFile {
    param([System.IO.FileInfo]$File)

    $issues = New-Object System.Collections.Generic.List[string]
    $archive = $null

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)

        $entryCount = 0

        foreach ($entry in $archive.Entries) {
            $entryCount++

            if ($entry.FullName.EndsWith("/")) {
                continue
            }

            $entryStream = $entry.Open()

            try {
                $buffer = New-Object byte[] 65536

                while ($entryStream.Read($buffer, 0, $buffer.Length) -gt 0) { }
            }
            finally {
                $entryStream.Dispose()
            }
        }

        if ($entryCount -eq 0) {
            $issues.Add("zip archive has no entries")
        }
    }
    catch {
        $issues.Add("zip validation failed: $($_.Exception.Message)")
    }
    finally {
        if ($archive) {
            $archive.Dispose()
        }
    }

    return $issues.ToArray()
}

function Test-OfficePackage {
    param(
        [System.IO.FileInfo]$File,
        [string]$Kind
    )

    $issues = New-Object System.Collections.Generic.List[string]

    $zipIssues = @(Test-ZipFile -File $File)

    foreach ($issue in $zipIssues) {
        $issues.Add($issue)
    }

    if ($zipIssues.Count -gt 0) {
        return $issues.ToArray()
    }

    $requiredEntries = @{
        ".docx" = @("[Content_Types].xml", "word/document.xml")
        ".xlsx" = @("[Content_Types].xml", "xl/workbook.xml")
        ".pptx" = @("[Content_Types].xml", "ppt/presentation.xml")
    }

    $archive = $null

    try {
        $archive = [System.IO.Compression.ZipFile]::OpenRead($File.FullName)

        $entryNames = @{}

        foreach ($entry in $archive.Entries) {
            $entryNames[$entry.FullName.ToLowerInvariant()] = $true
        }

        foreach ($required in $requiredEntries[$Kind]) {
            if (-not $entryNames.ContainsKey($required.ToLowerInvariant())) {
                $issues.Add("missing required Office entry: $required")
            }
        }
    }
    catch {
        $issues.Add("Office package inspection failed: $($_.Exception.Message)")
    }
    finally {
        if ($archive) {
            $archive.Dispose()
        }
    }

    return $issues.ToArray()
}

function Test-PdfFile {
    param([System.IO.FileInfo]$File)

    $issues = New-Object System.Collections.Generic.List[string]

    $header = [System.Text.Encoding]::ASCII.GetString(
        (Read-HeaderBytes -FilePath $File.FullName -Count ([Math]::Min(8, [int]$File.Length)))
    )

    if (-not $header.StartsWith("%PDF-")) {
        $issues.Add("PDF header is missing")
    }

    $tail = [System.Text.Encoding]::ASCII.GetString(
        (Read-TailBytes -FilePath $File.FullName -FileLength $File.Length -Count 2048)
    )

    if ($tail -notmatch "%%EOF") {
        $issues.Add("PDF EOF marker was not found near the end of the file")
    }

    if ($tail -notmatch "startxref") {
        $issues.Add("PDF startxref marker was not found near the end of the file")
    }

    return $issues.ToArray()
}

function Test-JsonFile {
    param([System.IO.FileInfo]$File)

    try {
        $text = [System.IO.File]::ReadAllText($File.FullName)
        [void]($text | ConvertFrom-Json)
        return @()
    }
    catch {
        return @("JSON parse failed: $($_.Exception.Message)")
    }
}

function Test-XmlFile {
    param([System.IO.FileInfo]$File)

    try {
        $xml = New-Object System.Xml.XmlDocument
        $xml.PreserveWhitespace = $false
        $xml.Load($File.FullName)
        return @()
    }
    catch {
        return @("XML parse failed: $($_.Exception.Message)")
    }
}

function Test-ImageFile {
    param([System.IO.FileInfo]$File)

    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction SilentlyContinue

        $image = [System.Drawing.Image]::FromFile($File.FullName)

        try {
            [void]$image.Width
            [void]$image.Height
            $image.RawFormat.Guid | Out-Null
        }
        finally {
            $image.Dispose()
        }

        return @()
    }
    catch {
        return @("image decode failed: $($_.Exception.Message)")
    }
}

function Test-GzipFile {
    param([System.IO.FileInfo]$File)

    $fileStream = $null
    $gzipStream = $null

    try {
        $fileStream = [System.IO.File]::Open(
            $File.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        )

        $gzipStream = [System.IO.Compression.GZipStream]::new(
            $fileStream,
            [System.IO.Compression.CompressionMode]::Decompress
        )

        $buffer = New-Object byte[] 65536

        while ($gzipStream.Read($buffer, 0, $buffer.Length) -gt 0) { }

        return @()
    }
    catch {
        return @("gzip validation failed: $($_.Exception.Message)")
    }
    finally {
        if ($gzipStream) {
            $gzipStream.Dispose()
        }

        if ($fileStream) {
            $fileStream.Dispose()
        }
    }
}

function Test-SqliteFile {
    param([System.IO.FileInfo]$File)

    $issues = New-Object System.Collections.Generic.List[string]

    $headerBytes = Read-HeaderBytes -FilePath $File.FullName -Count ([Math]::Min(100, [int]$File.Length))

    $headerText = [System.Text.Encoding]::ASCII.GetString(
        $headerBytes,
        0,
        [Math]::Min(16, $headerBytes.Length)
    )

    if ($headerText -ne "SQLite format 3`0") {
        $issues.Add("SQLite header is missing")
        return $issues.ToArray()
    }

    if ($File.Length -lt 100) {
        $issues.Add("SQLite file is shorter than its 100-byte header")
        return $issues.ToArray()
    }

    $pageSize = ($headerBytes[16] -shl 8) + $headerBytes[17]

    if ($pageSize -eq 1) {
        $pageSize = 65536
    }

    if ($pageSize -lt 512 -or
        $pageSize -gt 65536 -or
        (($pageSize -band ($pageSize - 1)) -ne 0)) {

        $issues.Add("SQLite page size is invalid: $pageSize")
    }
    elseif (($File.Length % $pageSize) -ne 0) {
        $issues.Add("SQLite file size is not a multiple of page size $pageSize")
    }

    return $issues.ToArray()
}

function Test-MagicMismatch {
    param([System.IO.FileInfo]$File)

    if ($File.Length -eq 0) {
        return @()
    }

    $ext = $File.Extension.ToLowerInvariant()

    $header = Read-HeaderBytes -FilePath $File.FullName -Count ([Math]::Min(16, [int]$File.Length))

    $hex = ([BitConverter]::ToString($header)).Replace("-", "")
    $ascii = [System.Text.Encoding]::ASCII.GetString($header)

    switch ($ext) {
        ".pdf"  { if (-not $ascii.StartsWith("%PDF-")) { return @("file extension is .pdf but header does not look like PDF") } }
        ".zip"  { if (-not $hex.StartsWith("504B0304") -and -not $hex.StartsWith("504B0506") -and -not $hex.StartsWith("504B0708")) { return @("file extension is .zip but header does not look like ZIP") } }
        ".docx" { if (-not $hex.StartsWith("504B")) { return @("file extension is .docx but header does not look like ZIP/Office package") } }
        ".xlsx" { if (-not $hex.StartsWith("504B")) { return @("file extension is .xlsx but header does not look like ZIP/Office package") } }
        ".pptx" { if (-not $hex.StartsWith("504B")) { return @("file extension is .pptx but header does not look like ZIP/Office package") } }
        ".png"  { if (-not $hex.StartsWith("89504E470D0A1A0A")) { return @("file extension is .png but header does not look like PNG") } }
        ".jpg"  { if (-not $hex.StartsWith("FFD8FF")) { return @("file extension is .jpg but header does not look like JPEG") } }
        ".jpeg" { if (-not $hex.StartsWith("FFD8FF")) { return @("file extension is .jpeg but header does not look like JPEG") } }
        ".gif"  { if (-not ($ascii.StartsWith("GIF87a") -or $ascii.StartsWith("GIF89a"))) { return @("file extension is .gif but header does not look like GIF") } }
        ".gz"   { if (-not $hex.StartsWith("1F8B")) { return @("file extension is .gz but header does not look like gzip") } }
        default { return @() }
    }

    return @()
}

function Test-File {
    param([System.IO.FileInfo]$File)

    $sha256 = ""

    $issues = New-Object System.Collections.Generic.List[string]
    $suspicious = New-Object System.Collections.Generic.List[string]

    try {
        $stream = [System.IO.File]::Open(
            $File.FullName,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        )

        $stream.Dispose()
    }
    catch {
        return New-CheckResult `
            -File $File `
            -Status "Error" `
            -Severity 3 `
            -Reason "file could not be opened for reading" `
            -Details $_.Exception.Message `
            -Sha256 $sha256
    }

    if ($File.Length -eq 0) {
        $suspicious.Add("file is zero bytes")
    }

    try {
        foreach ($issue in (Test-MagicMismatch -File $File)) {
            $issues.Add($issue)
        }
    }
    catch {
        $issues.Add("header inspection failed: $($_.Exception.Message)")
    }

    if ($File.Length -gt 0 -and $File.Length -le $maxDeepCheckBytes) {

        $ext = $File.Extension.ToLowerInvariant()

        try {
            switch ($ext) {
                ".zip"     { foreach ($issue in (Test-ZipFile -File $File)) { $issues.Add($issue) } }
                ".docx"    { foreach ($issue in (Test-OfficePackage -File $File -Kind ".docx")) { $issues.Add($issue) } }
                ".xlsx"    { foreach ($issue in (Test-OfficePackage -File $File -Kind ".xlsx")) { $issues.Add($issue) } }
                ".pptx"    { foreach ($issue in (Test-OfficePackage -File $File -Kind ".pptx")) { $issues.Add($issue) } }
                ".pdf"     { foreach ($issue in (Test-PdfFile -File $File)) { $issues.Add($issue) } }
                ".json"    { foreach ($issue in (Test-JsonFile -File $File)) { $issues.Add($issue) } }
                ".xml"     { foreach ($issue in (Test-XmlFile -File $File)) { $issues.Add($issue) } }
                ".svg"     { foreach ($issue in (Test-XmlFile -File $File)) { $issues.Add($issue) } }
                ".png"     { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".jpg"     { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".jpeg"    { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".gif"     { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".bmp"     { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".tif"     { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".tiff"    { foreach ($issue in (Test-ImageFile -File $File)) { $issues.Add($issue) } }
                ".gz"      { foreach ($issue in (Test-GzipFile -File $File)) { $issues.Add($issue) } }
                ".sqlite"  { foreach ($issue in (Test-SqliteFile -File $File)) { $issues.Add($issue) } }
                ".sqlite3" { foreach ($issue in (Test-SqliteFile -File $File)) { $issues.Add($issue) } }

                ".db" {
                    $header = [System.Text.Encoding]::ASCII.GetString(
                        (Read-HeaderBytes -FilePath $File.FullName -Count ([Math]::Min(16, [int]$File.Length)))
                    )

                    if ($header -eq "SQLite format 3`0") {
                        foreach ($issue in (Test-SqliteFile -File $File)) {
                            $issues.Add($issue)
                        }
                    }
                }
            }
        }
        catch {
            $issues.Add("deep validation failed: $($_.Exception.Message)")
        }
    }
    elseif ($File.Length -gt $maxDeepCheckBytes) {
        $suspicious.Add("deep checks skipped because file is over ${MaxDeepCheckMB}MB")
    }

    if ($IncludeHashes) {
        try {
            $sha256 = Get-Sha256 -File $File
        }
        catch {
            $suspicious.Add("hashing failed: $($_.Exception.Message)")
        }
    }

    if ($issues.Count -gt 0) {
        return New-CheckResult `
            -File $File `
            -Status "Corrupt" `
            -Severity 3 `
            -Reason (Join-Issue -Issues $issues.ToArray()) `
            -Details (Join-Issue -Issues $suspicious.ToArray()) `
            -Sha256 $sha256
    }

    if ($suspicious.Count -gt 0) {
        return New-CheckResult `
            -File $File `
            -Status "Suspicious" `
            -Severity 1 `
            -Reason (Join-Issue -Issues $suspicious.ToArray()) `
            -Details "" `
            -Sha256 $sha256
    }

    return New-CheckResult `
        -File $File `
        -Status "OK" `
        -Severity 0 `
        -Reason "" `
        -Details "" `
        -Sha256 $sha256
}

# =========================================================
# CHANGED SECTION:
# Only scan:
#   - files in the root folder
#   - files in immediate child folders
# No deeper recursion.
# =========================================================

$files = @()

foreach ($item in $resolvedItems) {

    if ($item.PSIsContainer) {

        # Files directly inside the root folder
        $files += @(Get-ChildItem `
            -LiteralPath $item.FullName `
            -File `
            -Force `
            -ErrorAction SilentlyContinue)

        # Immediate subfolders only
        $subfolders = @(Get-ChildItem `
            -LiteralPath $item.FullName `
            -Directory `
            -Force `
            -ErrorAction SilentlyContinue)

        foreach ($subfolder in $subfolders) {

            # Files inside each immediate subfolder
            $files += @(Get-ChildItem `
                -LiteralPath $subfolder.FullName `
                -File `
                -Force `
                -ErrorAction SilentlyContinue)
        }
    }
    else {
        $files += @($item)
    }
}

$files = @($files | Sort-Object -Property FullName -Unique)

if (-not $IncludeHidden) {
    $files = @(
        $files | Where-Object {
            -not ($_.Attributes -band [System.IO.FileAttributes]::Hidden)
        }
    )
}

if ($normalizedExtensions.Count -gt 0) {
    $files = @(
        $files | Where-Object {
            $normalizedExtensions -contains $_.Extension.ToLowerInvariant()
        }
    )
}

$results = New-Object System.Collections.Generic.List[object]

$total = $files.Count
$index = 0

foreach ($file in $files) {

    $index++

    if ($index -eq 1 -or $index % 100 -eq 0) {
        Write-Progress `
            -Activity "Checking files" `
            -Status "$index of $total" `
            -PercentComplete (($index / [Math]::Max($total, 1)) * 100)
    }

    $results.Add((Test-File -File $file))
}

Write-Progress -Activity "Checking files" -Completed

$orderedResults = @(
    $results | Sort-Object -Property Severity, Path -Descending
)

$summary = @(
    $results |
    Group-Object Status |
    Sort-Object Name |
    Select-Object Name, Count
)

Write-Host ""
Write-Host "Checked $total file(s) from $scanLabel"

foreach ($row in $summary) {
    Write-Host ("{0,-12} {1,6}" -f $row.Name, $row.Count)
}

$problemResults = @(
    $results |
    Where-Object { $_.Status -ne "OK" } |
    Sort-Object -Property Severity, Path -Descending
)

if ($problemResults.Count -gt 0) {

    Write-Host ""
    Write-Host "Files needing attention:"

    $problemResults |
        Select-Object Status, RelativePath, Reason, Details |
        Format-Table -AutoSize -Wrap
}
else {

    Write-Host ""
    Write-Host "No obvious corruption found."
}

if ($ReportPath) {

    $fullReportPath = $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($ReportPath)

    $orderedResults |
        Export-Csv `
            -Path $fullReportPath `
            -NoTypeInformation `
            -Encoding UTF8

    Write-Host "CSV report: $fullReportPath"
}

if ($JsonPath) {

    $fullJsonPath = $ExecutionContext.SessionState.Path.
        GetUnresolvedProviderPathFromPSPath($JsonPath)

    $orderedResults |
        ConvertTo-Json -Depth 4 |
        Set-Content `
            -Path $fullJsonPath `
            -Encoding UTF8

    Write-Host "JSON report: $fullJsonPath"
}
