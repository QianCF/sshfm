<#
    sshfm - Windows wrapper for build.sh

    Runs the standalone build inside WSL.  Usage:

        .\build.ps1              # normal build
        .\build.ps1 --clean      # wipe the cache and rebuild everything
        .\build.ps1 --jobs 8     # parallel jobs

    Requires a WSL distribution with g++, cmake, make, perl and tar.
#>
param([Parameter(ValueFromRemainingArguments = $true)]$Args)

$ErrorActionPreference = "Stop"

$pkg = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $pkg) { $pkg = (Get-Location).Path }

# convert  D:\sshfm  ->  /mnt/d/sshfm
$drive = $pkg.Substring(0, 1).ToLower()
$rest  = $pkg.Substring(2).Replace('\', '/')
$wslPath = "/mnt/$drive$rest"

Write-Host "sshfm build (WSL): $wslPath/build.sh $Args"
wsl.exe -e bash "$wslPath/build.sh" @Args
exit $LASTEXITCODE
