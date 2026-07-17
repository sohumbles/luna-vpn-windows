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
        if ($_.InvocationInfo.PositionMessage) {
            Write-Host "       $($_.InvocationInfo.PositionMessage.Trim())" -ForegroundColor DarkRed
        }
    }
}

$boundaryValues = @(
    [int64]2147483647,
    [int64]2147483648,
    [int64]2148533168,
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

Invoke-Test 'Anonymous report sanitizer removes client secrets and identifiers' {
    $input='Failed vless://secret@example.test UUID=8c0af1be-760f-4a69-bed8-0dc529a3d671 IP 72.56.116.159 C:\Users\Dima\AppData token=abcd1234'
    $safe=Protect-LunaAnonymousReportText $input
    Assert-True (-not $safe.Contains('vless://')) 'Proxy link must be removed'
    Assert-True (-not $safe.Contains('8c0af1be')) 'UUID must be removed'
    Assert-True (-not $safe.Contains('72.56.116.159')) 'IP must be removed'
    Assert-True (-not $safe.Contains('C:\Users\Dima')) 'User path must be removed'
    Assert-True (-not $safe.Contains('abcd1234')) 'Token must be removed'
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

Invoke-Test 'Luna Auto cache is DPAPI protected and manifest stays logical' {
    Add-Type -AssemblyName System.Security
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($applicationSource,[ref]$tokens,[ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count 'Luna application source must parse'
    foreach ($functionName in @('Get-Or','Get-LunaObjectValue','Protect-LunaAutoValue','Unprotect-LunaAutoValue','ConvertTo-LocalProfile','ConvertTo-LunaAutoCandidateProfile','ConvertTo-LunaAutoProfile')) {
        $definition=$ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
        },$true)|Select-Object -First 1
        Assert-True ($null -ne $definition) "Function $functionName must exist"
        Invoke-Expression $definition.Extent.Text
    }
    $secret='luna-auto-test-token'
    $protected=Protect-LunaAutoValue $secret
    Assert-True ($protected -ne $secret) 'DPAPI output cannot contain the plaintext token'
    Assert-Equal $secret (Unprotect-LunaAutoValue $protected) 'DPAPI cache must round-trip for the current Windows user'
    $manifest=[pscustomobject]@{
        server=[pscustomobject]@{country='Netherlands';city='Amsterdam'}
        candidates=@(
            [pscustomobject]@{id='one';name='One';host='203.0.113.1';port=443;protocol='vless';uuid='00000000-0000-4000-8000-000000000001';network='tcp';security='reality';serverName='example.com';publicKey='public';shortId='01';fingerprint='chrome';priority=20;enabled=$true},
            [pscustomobject]@{id='two';name='Two';host='203.0.113.1';port=8443;protocol='vless';uuid='00000000-0000-4000-8000-000000000001';network='ws';security='tls';serverName='203.0.113.1';path='/luna';fingerprint='chrome';priority=30;enabled=$true}
        )
    }
    $logical=ConvertTo-LunaAutoProfile $manifest
    Assert-Equal 'luna-auto' $logical.id 'Only one logical Luna Auto row must be exposed'
    Assert-Equal 'luna-auto' $logical.source 'Logical row must use the dedicated source'
    Assert-Equal 2 @($logical.extra.autoCandidates).Count 'All transport candidates must stay behind the logical row'
}

Invoke-Test 'Luna Auto connection path ranks and verifies transport candidates' {
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    Assert-True ($applicationSource -match "AppVersion = '1\.5\.3-release'") 'Release version must be advanced'
    Assert-True ($applicationSource -match 'function\s+Get-LunaAutoCandidates') 'Luna Auto must rank transport candidates'
    Assert-True ($applicationSource -match 'function\s+Test-LunaProxyReady') 'Luna Auto must verify real HTTPS traffic through Xray'
    Assert-True ($applicationSource -match 'foreach\(\$candidate in @\(Get-LunaAutoCandidates \$p\)\)') 'Luna Auto must support candidate fallback'
    Assert-True ($applicationSource -match 'if\(-not \$p\.extra\.isLunaAuto\)') 'Existing profiles must retain their established connection branch'
    Assert-True ($applicationSource -match 'protectedAccessToken=Protect-LunaAutoValue') 'Access token must never be cached in plaintext'
    Assert-True ($applicationSource -match '\$snapshot\.profiles=@\(\$snapshot\.profiles\|Where-Object \{\[string\]\$_\.id -ne ''luna-auto''\}\)') 'Personal Luna Auto UUID must be excluded from state.json'
}

Invoke-Test 'Split Tunneling compiles to native Xray TUN routing' {
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    Assert-True ($applicationSource -match "protocol='tun'") 'Native Xray TUN inbound must exist'
    Assert-True ($applicationSource -match 'autoSystemRoutingTable=\$routes') 'TUN must install the Windows system route'
    Assert-True ($applicationSource -match "autoOutboundsInterface='auto'") 'Xray outbound loop protection must be enabled'
    Assert-True ($applicationSource -match 'process=\$processes') 'Application and game exclusions must compile to process rules'
    Assert-True ($applicationSource -match "splitDomains") 'Website exclusions must be persisted'
    Assert-True ($applicationSource -match "splitIps") 'IP and CIDR exclusions must be persisted'
    Assert-True ($applicationSource -match "Request-TunElevation") 'TUN must request Windows elevation when required'
    Assert-True ($applicationSource -match "luna\.split\.v2") 'Import/export schema must preserve the selected scope'
    Assert-True ($applicationSource.Contains('proxy-aware') -and $applicationSource.Contains('UDP')) 'System Proxy limitations must be explicit in the UI'
    Assert-True ($applicationSource -notmatch 'splitEnabled=\$true;\$State\.settings\.mode=''TUN''') 'Enabling split rules must not force TUN mode'
}

Invoke-Test 'System Proxy split routing uses PID EXE domains and IPv4 IPv6 CIDR' {
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    $embedded = [regex]::Match($applicationSource, "Add-Type -TypeDefinition @'\r?\n(?<code>[\s\S]*?)\r?\n'@ -ReferencedAssemblies 'System.Net.Http.dll'")
    Assert-True $embedded.Success 'Embedded proxy source must be available'
    if (-not ('LunaTrafficMeter' -as [type])) {
        Add-Type -TypeDefinition $embedded.Groups['code'].Value -ReferencedAssemblies 'System.Net.Http.dll'
    }
    Assert-True ([LunaTrafficMeter]::TestRouteDecision('C:\Games\LunaTest\game.exe', 'unrelated.test', [string[]]@('C:\Games\LunaTest\game.exe'), [string[]]@(), [string[]]@())) 'Exact executable path must route direct'
    Assert-True ([LunaTrafficMeter]::TestRouteDecision('C:\Other.exe', 'api.example.com', [string[]]@(), [string[]]@('example.com'), [string[]]@())) 'Domain rule must include subdomains'
    Assert-True (-not [LunaTrafficMeter]::TestRouteDecision('C:\Other.exe', 'example.com', [string[]]@(), [string[]]@('*.example.com'), [string[]]@())) 'Wildcard must not include the apex'
    Assert-True ([LunaTrafficMeter]::TestRouteDecision('C:\Other.exe', '203.0.113.29', [string[]]@(), [string[]]@(), [string[]]@('203.0.113.0/24'))) 'IPv4 CIDR must match'
    Assert-True ([LunaTrafficMeter]::TestRouteDecision('C:\Other.exe', '2001:db8::29', [string[]]@(), [string[]]@(), [string[]]@('2001:db8::/32'))) 'IPv6 CIDR must match'
    Assert-True (-not [LunaTrafficMeter]::TestRouteDecision('C:\Other.exe', 'example.net', [string[]]@(), [string[]]@('example.com'), [string[]]@())) 'Unmatched traffic must remain on the Xray upstream'
}

Invoke-Test 'Running process picker resolves durable executable paths' {
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    Assert-True ($applicationSource -match 'Name="AddRunningSplitApp"') 'Application card must expose the running-process picker'
    Assert-True ($applicationSource -match 'Name="AddRunningSplitGame"') 'Game card must expose the running-process picker'
    Assert-True ($applicationSource -match 'function\s+Get-LunaRunningProcessChoices') 'Process enumeration must be implemented'
    Assert-True ($applicationSource -match 'function\s+Show-RunningProcessPicker') 'Process picker window must be implemented'
    Assert-True ($applicationSource -match '\$State\.settings\[\$key\]=@\(\$State\.settings\[\$key\]\+\$paths') 'Selected processes must be stored by executable path'
    Assert-Equal ((Get-Process -Id $PID).Path.ToLowerInvariant()) ([LunaTrafficMeter]::ResolveProcessPath($PID).ToLowerInvariant()) 'PID must resolve to the full executable path'

    $tokens=$null;$parseErrors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($applicationSource,[ref]$tokens,[ref]$parseErrors)
    $definition=$ast.FindAll({param($node)$node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq 'Get-LunaRunningProcessChoices'},$true)|Select-Object -First 1
    Invoke-Expression $definition.Extent.Text
    $script:CoreProcess=$null
    $child=Start-Process -FilePath 'powershell.exe' -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 15' -WindowStyle Hidden -PassThru
    try{
        Start-Sleep -Milliseconds 300
        $choice=@(Get-LunaRunningProcessChoices|Where-Object {$_.PID -eq $child.Id})|Select-Object -First 1
        Assert-True ($null -ne $choice) 'A user process with an accessible EXE must appear in the picker'
        Assert-Equal $child.Id ([int]$choice.PID) 'Displayed PID must identify the running instance'
        Assert-True ([IO.File]::Exists([string]$choice.Path)) 'Displayed process path must point to an existing EXE'
    }finally{
        if($child -and -not $child.HasExited){Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue}
    }
}

Invoke-Test 'Selective CONNECT proxy bypasses Xray for the owning process' {
    if (-not ('LunaTrafficMeter' -as [type])) { throw 'LunaTrafficMeter test type was not compiled' }
    function Get-EphemeralPort {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start()
        $port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port
        $listener.Stop()
        return $port
    }
    $destinationPort = Get-EphemeralPort
    $socksListen = Get-EphemeralPort
    $httpListen = Get-EphemeralPort
    $destination = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $destinationPort)
    $destination.Start()
    try {
        $ownerPath = (Get-Process -Id $PID).Path
        [LunaTrafficMeter]::Start($socksListen, (Get-EphemeralPort), $httpListen, (Get-EphemeralPort), [string[]]@($ownerPath), [string[]]@(), [string[]]@())
        $accept = $destination.AcceptTcpClientAsync()
        $client = [Net.Sockets.TcpClient]::new()
        $client.Connect([Net.IPAddress]::Loopback, $httpListen)
        $stream = $client.GetStream()
        $request = [Text.Encoding]::ASCII.GetBytes("CONNECT 127.0.0.1:$destinationPort HTTP/1.1`r`nHost: 127.0.0.1:$destinationPort`r`n`r`n")
        $stream.Write($request, 0, $request.Length)
        $buffer = New-Object byte[] 256
        $read = $stream.Read($buffer, 0, $buffer.Length)
        $response = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        Assert-True ($response.StartsWith('HTTP/1.1 200')) 'Excluded process must receive a direct CONNECT tunnel'
        Assert-True ($accept.Wait(3000)) 'Direct destination must receive the bypassed connection'
        $destinationClient = $accept.Result
        $payload = [Text.Encoding]::ASCII.GetBytes('LUNA-SPLIT')
        $stream.Write($payload, 0, $payload.Length)
        $remoteBuffer = New-Object byte[] 32
        $remoteRead = $destinationClient.GetStream().Read($remoteBuffer, 0, $remoteBuffer.Length)
        Assert-Equal 'LUNA-SPLIT' ([Text.Encoding]::ASCII.GetString($remoteBuffer, 0, $remoteRead)) 'CONNECT tunnel must relay application bytes directly'
        $destinationClient.Close();$client.Close()
    }
    finally {
        [LunaTrafficMeter]::Stop()
        $destination.Stop()
    }
}

Invoke-Test 'Unmatched CONNECT proxy request is preserved for Xray upstream' {
    function Get-ProxyTestPort {
        $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
        $listener.Start();$port = ([Net.IPEndPoint]$listener.LocalEndpoint).Port;$listener.Stop();return $port
    }
    $upstreamPort = Get-ProxyTestPort
    $socksListen = Get-ProxyTestPort
    $httpListen = Get-ProxyTestPort
    $upstream = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, $upstreamPort)
    $upstream.Start()
    try {
        [LunaTrafficMeter]::Start($socksListen, (Get-ProxyTestPort), $httpListen, $upstreamPort, [string[]]@(), [string[]]@(), [string[]]@())
        $accept = $upstream.AcceptTcpClientAsync()
        $client = [Net.Sockets.TcpClient]::new();$client.Connect([Net.IPAddress]::Loopback, $httpListen)
        $stream = $client.GetStream()
        $requestText = "CONNECT example.invalid:443 HTTP/1.1`r`nHost: example.invalid:443`r`n`r`n"
        $request = [Text.Encoding]::ASCII.GetBytes($requestText);$stream.Write($request, 0, $request.Length)
        Assert-True ($accept.Wait(3000)) 'Xray upstream must receive unmatched traffic'
        $upstreamClient = $accept.Result
        $buffer = New-Object byte[] 512
        $read = $upstreamClient.GetStream().Read($buffer, 0, $buffer.Length)
        $received = [Text.Encoding]::ASCII.GetString($buffer, 0, $read)
        Assert-Equal $requestText $received 'CONNECT authority and headers must be preserved for Xray'
        $upstreamClient.Close();$client.Close()
    }
    finally {
        [LunaTrafficMeter]::Stop();$upstream.Stop()
    }
}

Invoke-Test 'JSON subscription outbound without tag builds in TUN mode' {
    $applicationPath = @(
        (Join-Path $PSScriptRoot '..\Luna.ps1'),
        (Join-Path $PSScriptRoot '..\src\Luna.ps1')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    $applicationSource = Get-Content -Raw -Encoding UTF8 $applicationPath
    $tokens = $null
    $parseErrors = $null
    $ast = [Management.Automation.Language.Parser]::ParseInput($applicationSource, [ref]$tokens, [ref]$parseErrors)
    Assert-Equal 0 @($parseErrors).Count 'Application source must parse before extracting configuration functions'
    foreach ($functionName in @('ConvertTo-Hashtable', 'Get-LunaObjectValue', 'Set-LunaObjectValue', 'Get-LunaRoutingRules', 'Add-LunaTunInbound', 'Build-XrayConfig')) {
        $definition = $ast.FindAll({
            param($node)
            $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $functionName
        }, $true) | Select-Object -First 1
        Assert-True ($null -ne $definition) "Function $functionName must exist"
        Invoke-Expression $definition.Extent.Text
    }
    $script:State = @{
        settings = @{
            mode = 'TUN'; localPort = 10808; enableIPv6 = $false; dns = '1.1.1.1'
            bypassLan = $false; blockAds = $false; blockDomains = ''; directDomains = ''
            splitEnabled = $false; splitDomains = @(); splitIps = @(); splitApps = @(); splitGames = @()
        }
    }
    $script:LogFile = Join-Path $env:TEMP 'luna-json-profile-regression.log'
    $rawConfig = @{
        inbounds = @(@{ listen = '127.0.0.1'; port = 10808; protocol = 'socks'; settings = @{ udp = $false } })
        outbounds = @(@{
            protocol = 'vless'
            settings = @{ vnext = @(@{ address = 'example.com'; port = 443; users = @(@{ id = '00000000-0000-4000-8000-000000000000'; encryption = 'none' }) }) }
            streamSettings = @{ network = 'tcp'; security = 'none' }
        })
        routing = @{ domainStrategy = 'IPIfNonMatch'; rules = @() }
    } | ConvertTo-Json -Depth 20 -Compress
    $profile = @{ extra = @{ isJson = $true }; raw = $rawConfig }
    $config = Build-XrayConfig $profile 10808
    $proxy = $config.outbounds | Where-Object { $_.protocol -eq 'vless' } | Select-Object -First 1
    Assert-True ($null -ne $proxy) 'Proxy outbound must be preserved'
    Assert-Equal 'proxy' $proxy['tag'] 'Proxy tag must be assigned to the outbound object rather than an Object array'
    Assert-Equal 1 @($config.inbounds | Where-Object { $_.protocol -eq 'tun' }).Count 'TUN inbound must be added'
}

$elapsed = [DateTimeOffset]::UtcNow - $script:StartedAt
Write-Host ''
Write-Host ('Luna 1.5.3 regression harness: {0} passed, {1} failed in {2:N2}s' -f $script:Passed, $script:Failed, $elapsed.TotalSeconds) -ForegroundColor $(if ($script:Failed -eq 0) { 'Green' } else { 'Red' })

if ($script:Failed -ne 0) { exit 1 }
exit 0
