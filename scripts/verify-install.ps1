param(
    [ValidateSet('Sandbox','Full','Cross')][string]$Mode = 'Sandbox',
    [string]$Go = 'go'
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
$project = Split-Path $repo -Parent
$lockPath = Join-Path $project '.heavy.lock'
$evidence = Join-Path $repo 'tmp\install-proof'
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$token = "$((& git -C $repo branch --show-current) -join '') $([DateTime]::UtcNow.ToString('o')) $PID"
$commands = [System.Collections.Generic.List[object]]::new()
$manifest = [ordered]@{ mode=$Mode; started_utc=[DateTime]::UtcNow.ToString('o'); outcome='running'; commands=$commands }
$held = $false
while (!$held) {
    try {
        $token = "$((& git -C $repo branch --show-current) -join '') $([DateTime]::UtcNow.ToString('o')) $PID"
        $f = [IO.File]::Open($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $b = [Text.Encoding]::UTF8.GetBytes($token)
        $f.Write($b,0,$b.Length); $f.Dispose(); $held = $true
    } catch [IO.IOException] {
        if (Test-Path -LiteralPath $lockPath) {
            $age = [DateTime]::UtcNow - (Get-Item -LiteralPath $lockPath).LastWriteTimeUtc
            if ($age.TotalMinutes -ge 20) { Remove-Item -LiteralPath $lockPath; continue }
            Write-Host "Heavy work busy: $(Get-Content -Raw -LiteralPath $lockPath). Retrying in 15 seconds."
        }
        Start-Sleep -Seconds 15
    }
}
$saved = @{}
$keys = @('HOME','USERPROFILE','APPDATA','LOCALAPPDATA','GOPATH','GOCACHE','GOMODCACHE','RALX_TEST_BINARY','GOOS','GOARCH','CGO_ENABLED','RALX_URL','RALX_DATA','RALX_AGENT_KEY','RALX_AGENT_KEY_FILE','RALX_ADMIN_PIPE','CLAUDE_CONFIG_DIR','CODEX_HOME','XDG_CONFIG_HOME')
foreach ($k in $keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k) }
function Check([string]$Name,[string[]]$Arguments) {
    & $Go @Arguments 2>&1 | Tee-Object -FilePath (Join-Path $evidence "$Mode-$Name.log")
    $commands.Add(@{command="$Go $($Arguments -join ' ')"; exit_code=$LASTEXITCODE})
    if ($LASTEXITCODE -ne 0) { throw "$Name failed: $LASTEXITCODE" }
    Write-Host "$Name PASS"
}
try {
    Set-Location -LiteralPath $repo
    $manifest.sha = ((& git rev-parse HEAD) -join '').Trim()
    $manifest.branch = ((& git branch --show-current) -join '').Trim()
    $manifest.source_sha256 = @(& git ls-files --cached --others --exclude-standard | ForEach-Object {
        if (Test-Path -LiteralPath $_ -PathType Leaf) { @{path=$_;sha256=(Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant()} }
    })
    # Resolve build caches BEFORE moving HOME; no installed agent files are used.
    if (!$env:GOPATH) { $env:GOPATH = (& $Go env GOPATH).Trim() }
    if (!$env:GOCACHE) { $env:GOCACHE = (& $Go env GOCACHE).Trim() }
    if (!$env:GOMODCACHE) { $env:GOMODCACHE = (& $Go env GOMODCACHE).Trim() }
    $sandbox = Join-Path $evidence ('home-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $sandbox | Out-Null
    $env:HOME = $sandbox; $env:USERPROFILE = $sandbox
    $env:APPDATA = Join-Path $sandbox 'AppData\Roaming'; $env:LOCALAPPDATA = Join-Path $sandbox 'AppData\Local'
    foreach ($k in @('RALX_URL','RALX_DATA','RALX_AGENT_KEY','RALX_AGENT_KEY_FILE','RALX_ADMIN_PIPE','CLAUDE_CONFIG_DIR','CODEX_HOME')) { [Environment]::SetEnvironmentVariable($k,$null) }
    $env:XDG_CONFIG_HOME = Join-Path $sandbox '.config'
    if ($Mode -eq 'Cross') {
        $env:CGO_ENABLED = '0'
        foreach ($targetOS in @('windows','darwin','linux')) {
            foreach ($targetArch in @('amd64','arm64')) {
                $env:GOOS=$targetOS; $env:GOARCH=$targetArch
                Check "$targetOS-$targetArch" @('build','-mod=readonly','-trimpath','-o',(Join-Path $evidence "ralx_$($targetOS)_$targetArch"),'./cmd/ralx')
            }
        }
    } else {
        $env:RALX_TEST_BINARY = Join-Path $evidence 'ralx.exe'
        Check 'build' @('build','-mod=readonly','-o',$env:RALX_TEST_BINARY,'./cmd/ralx')
        if ($Mode -eq 'Full') {
            Check 'vet' @('vet','-mod=readonly','./...')
            Check 'tests' @('test','-mod=readonly','-p=1','./...','-count=1','-v')
        } else {
            Check 'tests' @('test','-mod=readonly','./internal/setupconfig','./cmd/ralx','-run','TestConfig|TestSetup|TestFreshCodex|TestAntigravity','-count=1','-v')
        }
    }
    $manifest.outcome = 'passed'
} catch {
    $manifest.outcome = 'failed'; $manifest.error = $_.Exception.Message
    throw
} finally {
    $manifest.finished_utc = [DateTime]::UtcNow.ToString('o')
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence "$Mode-manifest.json") -Encoding utf8
    foreach ($k in $keys) { [Environment]::SetEnvironmentVariable($k,$saved[$k]) }
    if ($held -and (Get-Content -Raw -LiteralPath $lockPath) -eq $token) { Remove-Item -LiteralPath $lockPath }
}
