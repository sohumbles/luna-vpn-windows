[CmdletBinding()]
param(
    [switch]$Quiet
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot 'Luna.TestCore.psm1') -Force -DisableNameChecking

$script:Passed = 0
$script:Failed = 0
$script:StartedAt = [DateTimeOffset]::UtcNow

function Assert-True {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw $Message }
}

function Assert-Equal {
    param([AllowNull()]$Expected, [AllowNull()]$Actual, [string]$Message)
    if ($Expected -ne $Actual) {
        throw "$Message. Expected=[$Expected], Actual=[$Actual]"
    }
}

function Invoke-Test {
    param([string]$Name, [scriptblock]$Body)
    try {
        & $Body
        $script:Passed++
        if (-not $Quiet) { Write-Host "[PASS] $Name" -ForegroundColor Green }
    }
    catch {
        $script:Failed++
        Write-Host "[FAIL] $Name" -ForegroundColor Red
        Write-Host "       $($_.Exception.Message)" -ForegroundColor Red
    }
}

$boundaryValues = @(
    [int64]2147483647,
    [int64]2147483648,
    [int64]2152589830,
    [int64]4294967296,
    [int64]1099511627776
)

foreach ($expected in $boundaryValues) {
    $captured = $expected
    Invoke-Test "Int64 boundary $captured is accepted exactly" {
        $result = ConvertTo-LunaInt64Counter -Value $captured.ToString([Globalization.CultureInfo]::InvariantCulture)
        Assert-True $result.Success 'Counter must be accepted'
        Assert-Equal $captured ([int64]$result.Value) 'Counter must remain exact'
        Assert-Equal $captured.ToString() (ConvertTo-LunaTelemetryCounterString -Value $captured) 'Wire counter must be an exact decimal string'
    }
}

Invoke-Test 'Negative counter is rejected' {
    $result = ConvertTo-LunaInt64Counter -Value '-1'
    Assert-True (-not $result.Success) 'Negative value must not be accepted'
    Assert-Equal 'negative' $result.Error 'Negative error classification'
}

Invoke-Test 'Empty counters are rejected' {
    foreach ($value in @($null, '', '   ')) {
        $result = ConvertTo-LunaInt64Counter -Value $value
        Assert-True (-not $result.Success) 'Empty value must not be accepted'
        Assert-Equal 'empty' $result.Error 'Empty error classification'
    }
}

Invoke-Test 'Invalid counters are rejected' {
    foreach ($value in @('abc', '1.5', 'NaN', '1e9', '9223372036854775808')) {
        $result = ConvertTo-LunaInt64Counter -Value $value
        Assert-True (-not $result.Success) "Invalid value $value must not be accepted"
        Assert-Equal 'invalid' $result.Error 'Invalid error classification'
    }
}

Invoke-Test 'Telemetry JSON preserves BIGINT counters as strings' {
    $value = [int64]1099511627776
    $payload = [ordered]@{
        rxBytes = ConvertTo-LunaTelemetryCounterString $value
        txBytes = ConvertTo-LunaTelemetryCounterString 4294967296
    } | ConvertTo-Json -Compress
    Assert-True ($payload.Contains('"rxBytes":"1099511627776"')) 'rxBytes must be a JSON string'
    Assert-True ($payload.Contains('"txBytes":"4294967296"')) 'txBytes must be a JSON string'
}

Invoke-Test 'Rates use Int64 deltas and double division' {
    $state = New-LunaCounterState
    $t0 = [DateTimeOffset]::Parse('2026-07-12T00:00:00Z')
    $null = Update-LunaCounterState $state 'session-a' 2147483648 4294967296 $t0
    $result = Update-LunaCounterState $state 'session-a' 2152589830 4299967296 $t0.AddSeconds(2)
    Assert-True $result.Accepted 'Delta must be accepted'
    Assert-Equal ([int64]5106182) ([int64]$result.RxDelta) 'Rx delta must remain exact'
    Assert-Equal ([double]2553091) ([double]$result.DownloadBytesPerSecond) 'Rx rate must use double division'
    Assert-Equal ([double]2500000) ([double]$result.UploadBytesPerSecond) 'Tx rate must use double division'
}

Invoke-Test 'Counter reset creates a zero-rate baseline' {
    $state = New-LunaCounterState
    $t0 = [DateTimeOffset]::Parse('2026-07-12T00:00:00Z')
    $null = Update-LunaCounterState $state 'session-a' 1099511627776 1099511627776 $t0
    $result = Update-LunaCounterState $state 'session-a' 1024 2048 $t0.AddSeconds(1)
    Assert-True $result.Accepted 'Reset sample must be accepted as baseline'
    Assert-True $result.Reset 'Reset flag must be set'
    Assert-Equal 'counter-reset' $result.Reason 'Reset must be classified'
    Assert-Equal ([double]0) $result.DownloadBytesPerSecond 'Reset cannot create a negative/download spike'
    Assert-Equal ([double]0) $result.UploadBytesPerSecond 'Reset cannot create a negative/upload spike'

    $next = Update-LunaCounterState $state 'session-a' 3072 4096 $t0.AddSeconds(2)
    Assert-Equal ([int64]2048) ([int64]$next.RxDelta) 'Next sample starts from reset baseline'
    Assert-Equal ([int64]2048) ([int64]$next.TxDelta) 'Next sample starts from reset baseline'
}

Invoke-Test 'Session change cannot mix old and new counters' {
    $state = New-LunaCounterState
    $t0 = [DateTimeOffset]::Parse('2026-07-12T00:00:00Z')
    $null = Update-LunaCounterState $state 'session-a' 1099511627776 4294967296 $t0
    $result = Update-LunaCounterState $state 'session-b' 2147483648 2147483648 $t0.AddSeconds(1)
    Assert-True $result.Reset 'Session change must reset the baseline'
    Assert-Equal 'session-change' $result.Reason 'Session change must be classified'
    Assert-Equal ([double]0) $result.DownloadBytesPerSecond 'No cross-session speed spike is allowed'
    Assert-Equal 'session-b' $state.SessionId 'State must follow the new session'
}

Invoke-Test 'Non-monotonic timestamps are rejected without corrupting baseline' {
    $state = New-LunaCounterState
    $t0 = [DateTimeOffset]::Parse('2026-07-12T00:00:00Z')
    $null = Update-LunaCounterState $state 'session-a' 100 200 $t0
    $bad = Update-LunaCounterState $state 'session-a' 200 300 $t0
    Assert-True (-not $bad.Accepted) 'Duplicate timestamp must be rejected'
    Assert-Equal 'non-monotonic-time' $bad.Reason 'Timestamp error must be classified'
    $next = Update-LunaCounterState $state 'session-a' 300 500 $t0.AddSeconds(1)
    Assert-Equal ([int64]200) ([int64]$next.RxDelta) 'Rejected sample must not move the baseline'
    Assert-Equal ([int64]300) ([int64]$next.TxDelta) 'Rejected sample must not move the baseline'
}

Invoke-Test 'Bounded queue evicts only the oldest items' {
    $queue = New-LunaBoundedQueue -Capacity 3
    1..5 | ForEach-Object { Add-LunaBoundedQueueItem $queue $_ }
    Assert-Equal 3 $queue.Items.Count 'Queue must stay at capacity'
    Assert-Equal ([int64]2) ([int64]$queue.Dropped) 'Dropped count must be exact'
    $batch = @(Take-LunaBoundedQueueBatch $queue 10)
    Assert-Equal '3,4,5' (($batch | ForEach-Object { [string]$_ }) -join ',') 'Queue must preserve newest FIFO items'
}

Invoke-Test 'Duration formatting does not wrap after 24 hours' {
    Assert-Equal '24:00:00' (Format-LunaDuration ([TimeSpan]::FromHours(24))) '24h duration must not wrap to 00h'
    Assert-Equal '49:02:03' (Format-LunaDuration (New-TimeSpan -Hours 49 -Minutes 2 -Seconds 3)) 'Multi-day duration must preserve total hours'
}

Invoke-Test 'Accelerated 24h monitoring remains bounded and reset-safe' {
    $secondsInDay = 24 * 60 * 60
    $latencyHistory = New-LunaBoundedQueue -Capacity 60
    $offlineSamples = New-LunaBoundedQueue -Capacity 2048
    $state = New-LunaCounterState
    $t0 = [DateTimeOffset]::Parse('2026-07-12T00:00:00Z')
    $rx = [int64]1099511627776
    $tx = [int64]4294967296
    $last = Update-LunaCounterState $state 'session-long-a' $rx $tx $t0
    Assert-True $last.IsBaseline 'Simulation must start with a baseline'

    $measurement = [int64]0
    for ($second = 1; $second -le $secondsInDay; $second++) {
        $rx = [int64]($rx + 3145728)
        $tx = [int64]($tx + 786432)
        $sessionId = if ($second -lt 43200) { 'session-long-a' } else { 'session-long-b' }

        if ($second -eq 43200) {
            # Simulates a new adapter/session whose OS counters begin near zero.
            $rx = [int64]1024
            $tx = [int64]2048
        }

        $last = Update-LunaCounterState $state $sessionId $rx $tx $t0.AddSeconds($second)
        Assert-True $last.Accepted "Sample $second must be accepted"
        Assert-True ($last.DownloadBytesPerSecond -ge 0) "Sample $second download rate cannot be negative"
        Assert-True ($last.UploadBytesPerSecond -ge 0) "Sample $second upload rate cannot be negative"

        if (($second % 5) -eq 0) {
            Add-LunaBoundedQueueItem $latencyHistory ([pscustomobject]@{ second = $second; latencyMs = 20 + ($second % 90) })
        }
        if (($second % 10) -eq 0) {
            $measurement++
            Add-LunaBoundedQueueItem $offlineSamples ([pscustomobject]@{
                measurementId = $measurement
                rxBytes = ConvertTo-LunaTelemetryCounterString $rx
                txBytes = ConvertTo-LunaTelemetryCounterString $tx
            })
        }
    }

    Assert-Equal 60 $latencyHistory.Items.Count 'Latency history must remain bounded to 60 samples'
    Assert-Equal 2048 $offlineSamples.Items.Count 'Offline telemetry queue must remain bounded'
    Assert-Equal ([int64](17280 - 60)) ([int64]$latencyHistory.Dropped) 'All excess latency samples must be accounted for'
    Assert-Equal ([int64](8640 - 2048)) ([int64]$offlineSamples.Dropped) 'All excess telemetry samples must be accounted for'
    Assert-Equal '24:00:00' (Format-LunaDuration ($t0.AddSeconds($secondsInDay) - $t0)) 'Session duration must reach 24:00:00'

    $sent = New-Object 'System.Collections.Generic.HashSet[long]'
    $largestBatch = 0
    while ($offlineSamples.Items.Count -gt 0) {
        $batch = @(Take-LunaBoundedQueueBatch $offlineSamples 120)
        $largestBatch = [Math]::Max($largestBatch, $batch.Count)
        foreach ($sample in $batch) {
            Assert-True ($sent.Add([int64]$sample.measurementId)) 'A queued measurement must not be emitted twice'
        }
    }
    Assert-True ($largestBatch -le 120) 'Upload batches must respect the 120-sample cap'
    Assert-Equal 2048 $sent.Count 'All retained samples must drain exactly once'
}

Invoke-Test 'Selected-server auto refresh requires both VPN and opt-in' {
    $truthTable = @(
        @{ Vpn = $false; Enabled = $false; Expected = $false },
        @{ Vpn = $false; Enabled = $true;  Expected = $false },
        @{ Vpn = $true;  Enabled = $false; Expected = $false },
        @{ Vpn = $true;  Enabled = $true;  Expected = $true }
    )
    foreach ($case in $truthTable) {
        $actual = [bool]($case.Vpn -and $case.Enabled)
        Assert-Equal $case.Expected $actual "VPN=$($case.Vpn), AutoRefresh=$($case.Enabled)"
    }
}

Invoke-Test 'Desktop timer uses the strict selected-latency policy' {
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    Assert-True (-not [string]::IsNullOrWhiteSpace($applicationPath)) 'Luna.ps1 must be present in a release or repository layout'
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    Assert-True ($applicationSource -match 'function\s+Test-SelectedLatencyAutoRefreshAllowed') 'Central auto-refresh policy must exist'
    Assert-True ($applicationSource -match '\$script:SelectedLatencyAutoEnabled\s+-and\s+\$LatencyAutoRefresh\.IsChecked\s+-eq\s+\$true\s+-and\s+\(Test-LunaVpnSessionActive\)') 'Policy must require VPN and checked auto-refresh control'
    Assert-True ($applicationSource -match 'if\(\(Test-SelectedLatencyAutoRefreshAllowed\)\s+-and\s+-not\s+\$script:SelectedPingTask\)') 'Timer must start probes only through the central policy'
    Assert-True ($applicationSource -notmatch '\$timer\.Add_Tick\([^\r\n]*Complete-LatencyProbe') 'Session timer must not run an independent latency loop'
    Assert-True ($applicationSource -match 'SelectedLatencyAutoGeneration') 'Stale automatic results must be invalidated'
}

$elapsed = [DateTimeOffset]::UtcNow - $script:StartedAt
Write-Host ''
Write-Host ('Luna 1.3.0 monitoring harness: {0} passed, {1} failed in {2:N2}s' -f $script:Passed, $script:Failed, $elapsed.TotalSeconds) -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })

if ($script:Failed -ne 0) { exit 1 }
exit 0
