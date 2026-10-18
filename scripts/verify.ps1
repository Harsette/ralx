param(
    [ValidateSet('Bootstrap','Doctor','Fast','Full','Race')][string]$Mode = 'Fast',
    [string]$Go = 'go',
    [string]$EvidenceDir = 'tmp/verification',
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$repo = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $repo
$evidence = [System.IO.Path]::GetFullPath((Join-Path $repo $EvidenceDir))
New-Item -ItemType Directory -Force -Path $evidence | Out-Null
$env:GOTOOLCHAIN = 'local'
if ($Offline) { $env:GOPROXY = 'off' }
$previousCGO = $env:CGO_ENABLED
if ($Mode -eq 'Race') { $env:CGO_ENABLED = '1' }
$env:GOCACHE = Join-Path ([System.IO.Path]::GetTempPath()) 'ralx-remediation-gocache'
$env:GOTMPDIR = Join-Path ([System.IO.Path]::GetTempPath()) 'ralx-remediation-gotmp'
New-Item -ItemType Directory -Force -Path $env:GOTMPDIR | Out-Null
$commands = [System.Collections.Generic.List[object]]::new()
$manifest = [ordered]@{
    repository = 'Harsette/ralx'; mode = $Mode; started_utc = [DateTime]::UtcNow.ToString('o')
    candidate_sha = ((& git rev-parse HEAD) -join '').Trim()
    branch = ((& git branch --show-current) -join '').Trim()
    os = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
    architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
    offline = [bool]$Offline; go_toolchain = 'local'; cgo_enabled_override = $env:CGO_ENABLED; cc_override = $env:CC; outcome = 'running'; commands = $commands
    limits = @('Synthetic fixtures and loopback test servers only. No live-account verification.', 'No installed service, vault ACL, tunnel, deployment or security certification proof.', 'Browser screenshots/manual design acceptance are separate from these fixture journeys.')
}
$mutex = $null
$held = $false
function Invoke-Check([string]$Name, [string[]]$Arguments) {
    $log = Join-Path $evidence ($Name + '.log')
    $entry = [ordered]@{ command = "$Go $($Arguments -join ' ')"; log = $log; exit_code = $null }
    $commands.Add($entry)
    & $Go @Arguments 2>&1 | Out-File -LiteralPath $log -Encoding utf8
    $entry.exit_code = $LASTEXITCODE
    Write-Host "$Name : exit $($entry.exit_code) ($log)"
    if ($entry.exit_code -ne 0) { Get-Content -LiteralPath $log -Tail 30; throw "$Name failed" }
}
try {
    $manifest.go_version = ((& $Go version 2>&1) -join "`n")
    if ($LASTEXITCODE -ne 0) { throw 'Go is unavailable' }
    $manifest.working_tree = @(& git status --short)
    $diffPath = Join-Path $evidence 'tracked.diff'
    & git diff --binary "--output=$diffPath"
    if ($LASTEXITCODE -ne 0) { throw 'Could not record tracked diff' }
    $sourceFiles = @(& git ls-files --cached --others --exclude-standard)
    $manifest.source_sha256 = @($sourceFiles | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | ForEach-Object {
        [ordered]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash.ToLowerInvariant() }
    })
    if ($Mode -eq 'Bootstrap') {
        Invoke-Check 'dependencies' @('mod','download')
    } elseif ($Mode -eq 'Doctor') {
        Invoke-Check 'modules' @('list','-mod=readonly','-deps','-test','./...')
        foreach ($path in @('CONTRIBUTING.md','SECURITY.md','internal/daemon/oauth_e2e_test.go')) {
            if (!(Test-Path -LiteralPath $path)) { throw "Missing required fixture/context: $path" }
        }
    } else {
        # One shared MSI mutex across all repository remediation tasks. Acquire
        # nonblocking so callers can coordinate without silently starting together.
        if ([System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([System.Runtime.InteropServices.OSPlatform]::Windows)) {
            $mutex = [System.Threading.Mutex]::new($false,'Local\RalX_HeavyVerify')
            try { $held = $mutex.WaitOne(0) } catch [System.Threading.AbandonedMutexException] { $held = $true }
            if (!$held) { throw 'Heavy verification is busy; retry after its owner releases the shared mutex' }
        }
        if ($Mode -eq 'Race') {
            # Missing compiler/race support fails this required security gate.
            # Instrumented complete-catalog transform checks are CPU intensive.
            # Retain all cases with an explicit finite per-package time bound.
            Invoke-Check 'race' @('test','-mod=readonly','-race','-timeout=30m','-p=1','./...','-count=1')
        } else {
            Invoke-Check 'vet' @('vet','-mod=readonly','./...')
            if ($Mode -eq 'Fast') {
                Invoke-Check 'security' @('test','-mod=readonly','-p=1','./internal/...','-run','Astra|Fix|Daru','-count=1')
            } else {
                Invoke-Check 'full-tests' @('test','-mod=readonly','-p=1','./...','-count=1')
                Invoke-Check 'journeys' @('test','-mod=readonly','-p=1','./internal/daemon','-run','OAuth|MCP|Approval|Upload|Gate|Revoke|Astra8','-count=1','-v')
                Invoke-Check 'build' @('build','-mod=readonly','-o',(Join-Path $evidence 'ralx-candidate'),'./cmd/ralx')
            }
        }
    }
    $manifest.outcome = 'passed'
} catch {
    $manifest.outcome = 'failed'
    $manifest.failure = $_.Exception.Message
    Write-Host $manifest.failure
} finally {
    if ($Mode -eq 'Race') { $env:CGO_ENABLED = $previousCGO }
    if ($held) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
    $manifest.finished_utc = [DateTime]::UtcNow.ToString('o')
    $manifest | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'manifest.json') -Encoding utf8
}
if ($manifest.outcome -ne 'passed') { exit 1 }
