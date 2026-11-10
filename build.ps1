# Builds the bypass DLL, the injector and the .pkz unpacker (x64 Release).
# Usage:  powershell -ExecutionPolicy Bypass -File .\build.ps1
$ErrorActionPreference = 'Stop'

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) {
    throw "vswhere.exe not found - install Visual Studio with the C++ workload."
}

$msbuild = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" |
    Select-Object -First 1
if (-not $msbuild) {
    throw "MSBuild not found."
}

Write-Host "Using $msbuild"
& $msbuild "$PSScriptRoot\MXB-Bypass.sln" /m /p:Configuration=Release /p:Platform=x64
if ($LASTEXITCODE -ne 0) {
    throw "Build failed ($LASTEXITCODE)."
}

Write-Host ""
Write-Host "Output:"
Get-ChildItem "$PSScriptRoot\bin\x64\Release" -Recurse -File |
    Where-Object { $_.Extension -in '.exe', '.dll' } |
    Select-Object @{Name='File';Expression={$_.FullName.Substring($PSScriptRoot.Length + 1)}}, Length
