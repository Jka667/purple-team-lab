<#
.SYNOPSIS
  Runs the Atomic Red Team tests listed in emulation-plan.csv and logs UTC start/end times,
  so check_detections.py can query Splunk for each detection in the right window.
.EXAMPLE
  .\Run-PurpleTest.ps1 -Cleanup
#>
param(
    [string]$Plan = "$PSScriptRoot\..\emulation-plan.csv",
    [string]$OutDir = "$PSScriptRoot\..\results",
    [string]$AtomicModule = "C:\AtomicRedTeam\invoke-atomicredteam\Invoke-AtomicRedTeam.psd1",
    [switch]$Cleanup
)

Import-Module $AtomicModule -Force
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$out = Join-Path $OutDir ("run-{0:yyyyMMdd-HHmmss}.csv" -f (Get-Date))

$rows = foreach ($t in Import-Csv $Plan) {
    Write-Host "== $($t.detection_id) | $($t.technique) | $($t.test_name)"
    Invoke-AtomicTest $t.technique -TestNames $t.test_name -GetPrereqs | Out-Null
    $start = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    Invoke-AtomicTest $t.technique -TestNames $t.test_name
    $end = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    if ($Cleanup) { Invoke-AtomicTest $t.technique -TestNames $t.test_name -Cleanup | Out-Null }
    [pscustomobject]@{
        detection_id = $t.detection_id
        technique    = $t.technique
        test_name    = $t.test_name
        host         = $env:COMPUTERNAME
        start_utc    = $start
        end_utc      = $end
    }
}

$rows | Export-Csv -Path $out -NoTypeInformation -Encoding UTF8
Write-Host "Results: $out  (wait a few minutes for indexing, then run check_detections.py)"
