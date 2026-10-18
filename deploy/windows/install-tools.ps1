# Install real CLIs into C:\Program Files\RalX\tools, where only admins can
# change them (RalX refuses to run tools a normal user could replace).
# Run elevated. Sources are prepared (downloaded + checksum-verified) first:
#   -NodeDir    unpacked official Node.js zip folder (node-vXX-win-x64)
#   -VercelDir  folder with node_modules\vercel (npm install vercel)
#   -Supabase   supabase.exe from the official release zip
param(
  [string]$NodeDir,
  [string]$VercelDir,
  [string]$Supabase,
  [string]$WranglerDir
)
$ErrorActionPreference = 'Stop'
$root = Join-Path $env:ProgramFiles 'RalX\tools'
New-Item -ItemType Directory -Force $root | Out-Null
if ($NodeDir) {
  robocopy $NodeDir (Join-Path $root 'node') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  Write-Output "node: $(Join-Path $root 'node\node.exe')"
}
if ($VercelDir) {
  robocopy (Join-Path $VercelDir 'node_modules') (Join-Path $root 'vercel\node_modules') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  Write-Output "vercel: $(Join-Path $root 'vercel\node_modules\vercel\dist\index.js')"
}
if ($Supabase) {
  New-Item -ItemType Directory -Force (Join-Path $root 'supabase') | Out-Null
  Copy-Item $Supabase (Join-Path $root 'supabase\supabase.exe') -Force
  Write-Output "supabase: $(Join-Path $root 'supabase\supabase.exe')"
}
if ($WranglerDir) {
  robocopy (Join-Path $WranglerDir 'node_modules') (Join-Path $root 'wrangler\node_modules') /MIR /NFL /NDL /NJH /NJS /NP | Out-Null
  Write-Output "wrangler: $(Join-Path $root 'wrangler\node_modules\wrangler\bin\wrangler.js')"
}
# Tools inherit Program Files' ACL (Users: read+execute only).
Restart-Service RalX
