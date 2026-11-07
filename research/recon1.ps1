# Runner for recon1.cs: compile with in-box csc and run against live valheim.
$ErrorActionPreference = 'Stop'
if (-not [Environment]::Is64BitProcess) { throw 'Need 64-bit PowerShell.' }

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$src  = Join-Path $here 'recon1.cs'
$out  = Join-Path $here 'recon1-output.txt'
$dll  = Join-Path $here 'recon1.dll'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) { throw "csc not found: $csc" }

& $csc /nologo /target:library /out:$dll /optimize+ $src
if ($LASTEXITCODE -ne 0) { throw "compile failed ($LASTEXITCODE)" }

Add-Type -Path $dll

$proc = Get-Process valheim -ErrorAction Stop
Write-Host "target: valheim pid=$($proc.Id)  (0x$($proc.Id.ToString('X')))"
$sw = [Diagnostics.Stopwatch]::StartNew()
[Recon1]::Run($proc.Id, $out)
$sw.Stop()
Write-Host "done in $($sw.Elapsed.TotalSeconds) s -> $out"
