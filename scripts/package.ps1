<#
  Builds the agent and produces a distributable package:
      dist\soc-agent-<version>\   soc-agent.exe, config.json, README.txt
      dist\soc-agent-<version>.zip

  On the target machine, from an Administrator terminal inside the unzipped folder:
      .\soc-agent.exe install
  Run from a Windows machine with Rust installed (cargo).
#>
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$be   = Join-Path $root 'backend'

Push-Location $be
cargo build --release
$ver = (Select-String -Path Cargo.toml -Pattern '^version\s*=\s*"(.+)"' | Select-Object -First 1).Matches.Groups[1].Value
Pop-Location

$out = Join-Path $root "dist\soc-agent-$ver"
Remove-Item $out -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item (Join-Path $be 'target\release\soc-agent.exe') $out
Copy-Item (Join-Path $be 'config.json') $out
Copy-Item (Join-Path $PSScriptRoot 'PACKAGE-README.txt') (Join-Path $out 'README.txt')

$zip = "$out.zip"
Remove-Item $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -Path "$out\*" -DestinationPath $zip
Write-Host "Package ready: $zip" -ForegroundColor Green
