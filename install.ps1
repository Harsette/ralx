# RalX per-user installer. No administrator privileges required.
# irm https://raw.githubusercontent.com/Harsette/ralx/main/install.ps1 | iex
$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne 'Win32NT') { throw 'Use install.sh on macOS or Linux.' }
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
if ($arch -eq 'x64') { $arch = 'amd64' }
if ($arch -notin @('amd64','arm64')) { throw "Unsupported architecture: $arch" }
$release = $env:RALX_RELEASE_BASE_URL
if (!$release) {
    if ($env:RALX_VERSION) { $release = "https://github.com/Harsette/ralx/releases/download/$env:RALX_VERSION" }
    else { $release = 'https://github.com/Harsette/ralx/releases/latest/download' }
}
$asset = "ralx_windows_$arch.exe"
$userDir = [Environment]::GetFolderPath('UserProfile')
# os.UserHomeDir uses USERPROFILE on Windows; sandbox callers must set it.
if ($env:USERPROFILE) { $userDir = $env:USERPROFILE }
if ($env:RALX_SETUP_SANDBOX -eq '1') {
    foreach ($name in @('HOME','USERPROFILE','APPDATA','LOCALAPPDATA')) {
        $v = [Environment]::GetEnvironmentVariable($name)
        if (!$v -or !([IO.Path]::GetFullPath($v) + '\').StartsWith([IO.Path]::GetFullPath($userDir).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Sandbox requires $name inside temporary HOME" }
    }
}
$binDir = if ($env:RALX_INSTALL_DIR) { [IO.Path]::GetFullPath($env:RALX_INSTALL_DIR) } else { Join-Path $userDir '.local\bin' }
if ($env:RALX_SETUP_SANDBOX -eq '1' -and !($binDir + '\').StartsWith([IO.Path]::GetFullPath($userDir).TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Sandbox install directory must be inside temporary HOME.' }
$exe = Join-Path $binDir 'ralx.exe'
$receiptPath = Join-Path $userDir '.ralx\install.json'
$previous = $null
if (Test-Path -LiteralPath $receiptPath) { $previous = Get-Content -Raw -LiteralPath $receiptPath | ConvertFrom-Json }

$scratch = Join-Path ([IO.Path]::GetTempPath()) ('ralx-install-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch | Out-Null
function Get-ReleaseFile([string]$Name, [string]$Dest) {
    if ($release -match '^https?://') { Invoke-WebRequest -UseBasicParsing -Uri ($release.TrimEnd('/') + '/' + $Name) -OutFile $Dest }
    elseif ($release -match '^file:') { Copy-Item -LiteralPath (Join-Path ([uri]$release).LocalPath $Name) -Destination $Dest }
    else { Copy-Item -LiteralPath (Join-Path $release $Name) -Destination $Dest }
}
try {
    $download = Join-Path $scratch $asset
    Get-ReleaseFile $asset $download
    $checks = Join-Path $scratch 'checksums.txt'
    Get-ReleaseFile 'checksums.txt' $checks
    $matchesFound = @(Get-Content -LiteralPath $checks | Where-Object { $_ -match ('^[a-fA-F0-9]{64}\s+\*?' + [regex]::Escape($asset) + '$') })
    if ($matchesFound.Count -ne 1) { throw 'Release checksum is missing or duplicated.' }
    $expected = ($matchesFound[0] -split '\s+')[0]
    $sha = [Security.Cryptography.SHA256]::Create()
    $stream = [IO.File]::OpenRead($download)
    try { $actual = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-','') }
    finally { $stream.Dispose(); $sha.Dispose() }
    if ($actual -ne $expected) { throw 'The download check failed. Nothing was installed.' }
    # The checksum-verified binary owns detection, backup, upgrade and rollback.
    $upgradeOutput = @(& $download install-upgrade --target $exe 2>&1)
    $upgradeExit = $LASTEXITCODE
    $upgradeOutput | ForEach-Object { Write-Host $_ }
    if ($upgradeExit -ne 0) { throw 'RalX upgrade failed. Follow the diagnostic or printed rollback command.' }
    if ($upgradeOutput.Count -ne 1 -or [string]$upgradeOutput[0] -ne 'fresh') { return }
    New-Item -ItemType Directory -Force -Path $binDir, (Split-Path $receiptPath -Parent) | Out-Null
    Move-Item -LiteralPath $download -Destination $exe
    $added = $false
    if ($env:RALX_SETUP_SANDBOX -ne '1') {
        $userPath = [string][Environment]::GetEnvironmentVariable('Path','User')
        if ($binDir -notin ($userPath -split ';')) {
            [Environment]::SetEnvironmentVariable('Path',(($userPath.TrimEnd(';') + ';' + $binDir).TrimStart(';')),'User')
            $added = $true
        }
    }
    if ($previous) { $added = $added -or $previous.path_added }
    $json = @{ binary=$exe; path_added=$added; profile=''; profile_existed=$false } | ConvertTo-Json
    [IO.File]::WriteAllText($receiptPath, $json, [Text.UTF8Encoding]::new($false))
    $env:PATH = $binDir + ';' + $env:PATH
    Write-Host "Checked the download. Installed $exe"
    $setupArgs = @()
    if ($env:RALX_SETUP_ARGS_JSON) { $setupArgs = @(ConvertFrom-Json $env:RALX_SETUP_ARGS_JSON) }
    & $exe setup @setupArgs
    if ($LASTEXITCODE -ne 0) { throw "Installed, but setup needs attention. Retry: & '$exe' setup" }
    & $exe doctor
    if ($LASTEXITCODE -ne 0) { throw 'Doctor found an installation problem.' }
} finally {
    # Delete only this installer-created temporary directory.
    $tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    $resolvedScratch = [IO.Path]::GetFullPath($scratch)
    if (!$resolvedScratch.StartsWith($tempRoot,[StringComparison]::OrdinalIgnoreCase) -or !([IO.Path]::GetFileName($resolvedScratch)).StartsWith('ralx-install-')) { throw 'Refusing cleanup outside the installer temporary directory.' }
    Remove-Item -LiteralPath $scratch -Recurse -Force
}
