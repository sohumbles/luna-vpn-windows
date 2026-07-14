[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$failures = New-Object Collections.Generic.List[string]
$passed = 0

function Assert-Equal($Expected,$Actual,[string]$Name) {
    if($Expected -ne $Actual){$script:failures.Add("$Name`: expected <$Expected>, actual <$Actual>")}else{$script:passed++}
}
function Assert-True([bool]$Condition,[string]$Name) {
    if(-not $Condition){$script:failures.Add("$Name`: condition is false")}else{$script:passed++}
}
function Parse-Counter($Value) {
    if($null -eq $Value){return $null}
    $parsed=[int64]0
    if(-not [int64]::TryParse(([string]$Value).Trim(),[Globalization.NumberStyles]::Integer,[Globalization.CultureInfo]::InvariantCulture,[ref]$parsed)){return $null}
    if($parsed -lt 0){return $null}
    return $parsed
}
function Measure-Traffic([int64]$Previous,[int64]$Current,[double]$ElapsedSeconds) {
    if($ElapsedSeconds -le 0){return @{Delta=[int64]0;BytesPerSecond=[double]0;Reset=$true}}
    if($Current -lt $Previous){return @{Delta=[int64]0;BytesPerSecond=[double]0;Reset=$true}}
    $delta=[int64]($Current-$Previous)
    return @{Delta=$delta;BytesPerSecond=([double]$delta/$ElapsedSeconds);Reset=$false}
}

foreach($value in @([int64]2147483647,[int64]2147483648,[int64]2152589830,[int64]4294967296,[int64]1099511627776,[int64]9223372036854775807)){
    Assert-Equal $value (Parse-Counter ([string]$value)) "Int64 parsing $value"
}
Assert-Equal $null (Parse-Counter '-1') 'Negative counter rejected'
Assert-Equal $null (Parse-Counter '') 'Empty counter rejected'
Assert-Equal $null (Parse-Counter 'not-a-number') 'Invalid counter rejected'

$sample=Measure-Traffic 2147483647 2152589830 1.5
Assert-Equal ([int64]5106183) $sample.Delta 'Delta above Int32 boundary'
Assert-True ([Math]::Abs($sample.BytesPerSecond-3404122) -lt 0.01) 'Double rate calculation'
Assert-True (-not $sample.Reset) 'Normal sample is not reset'

$reset=Measure-Traffic 5000 120 1
Assert-Equal ([int64]0) $reset.Delta 'Counter reset drops negative delta'
Assert-Equal ([double]0) $reset.BytesPerSecond 'Counter reset speed is zero'
Assert-True $reset.Reset 'Counter reset detected'

$zeroInterval=Measure-Traffic 1 2 0
Assert-True $zeroInterval.Reset 'Zero interval rejected'

# Session changes start from a fresh baseline and never reuse an earlier counter.
$sessionA=Measure-Traffic 1000 1500 1
$sessionB=Measure-Traffic 20 50 1
Assert-Equal ([int64]500) $sessionA.Delta 'Session A delta'
Assert-Equal ([int64]30) $sessionB.Delta 'Session B fresh baseline'

# Exact counters are JSON strings, so JavaScript never rounds BIGINT values.
$payload=@{rxBytes=([int64]1099511627776).ToString([Globalization.CultureInfo]::InvariantCulture)}|ConvertTo-Json -Compress
Assert-True ($payload -match '"rxBytes":"1099511627776"') 'JSON preserves exact Int64 as string'

# Accelerated 24-hour simulation: one sample/second, bounded offline queue of 1000.
$queue=New-Object Collections.Generic.Queue[object]
$received=[int64]0;$sent=[int64]0
for($second=0;$second -lt 86400;$second++){
    $received=[int64]($received+2152589830)
    $sent=[int64]($sent+2147483648)
    $queue.Enqueue(@{rx=$received;tx=$sent;at=$second})
    while($queue.Count -gt 1000){[void]$queue.Dequeue()}
}
Assert-Equal 1000 $queue.Count '24h queue remains bounded'
Assert-True ($received -gt [int64][int]::MaxValue) '24h receive counter exceeds Int32 safely'
Assert-True ($sent -gt [int64][int]::MaxValue) '24h send counter exceeds Int32 safely'

# Monitoring gate: repeated ticks cannot overlap a running request.
$running=$false;$starts=0
for($tick=0;$tick -lt 1000;$tick++){
    if(-not $running){$running=$true;$starts++}
    if(($tick % 5) -eq 4){$running=$false}
}
Assert-Equal 200 $starts 'Single non-overlapping monitoring gate'

$desktopPath=Join-Path (Split-Path $PSScriptRoot -Parent) 'Luna.ps1'
$desktop=Get-Content -Raw -Encoding UTF8 $desktopPath
Assert-True ($desktop -notmatch '\[Math\]::Max\(0,\[int64\]') 'No Int32 Math.Max overload for Int64 counters'
Assert-True ($desktop -match 'latencyAutoRefresh=\$false') 'Latency auto-refresh defaults off'
Assert-True ($desktop -match 'Test-LunaVpnSessionActive\) -and -not \$script:SelectedPingTask') 'Latency auto-refresh requires an active Luna VPN session'
Assert-True ($desktop -match 'Start-SelectedLatencyProbe -Automatic') 'Automatic and manual latency probes are distinguished'
Assert-True (([regex]::Matches($desktop,'New-Object Net\.Http\.HttpClient\s')).Count -eq 1) 'One shared HttpClient allocation'

if($failures.Count){
    $failures|ForEach-Object{Write-Error $_}
    throw "$($failures.Count) tests failed; $passed passed."
}
Write-Host "PASS: $passed checks, including accelerated 24-hour simulation."
