Set-StrictMode -Version 2.0

function ConvertTo-LunaInt64Counter {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [AllowNull()]
        [object]$Value
    )

    if ($null -eq $Value) {
        return [pscustomobject]@{ Success = $false; Value = [int64]0; Error = 'empty' }
    }

    $text = [Convert]::ToString($Value, [Globalization.CultureInfo]::InvariantCulture)
    if ([string]::IsNullOrWhiteSpace($text)) {
        return [pscustomobject]@{ Success = $false; Value = [int64]0; Error = 'empty' }
    }

    $parsed = [int64]0
    $style = [Globalization.NumberStyles]::Integer
    $ok = [int64]::TryParse($text.Trim(), $style, [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed)
    if (-not $ok) {
        return [pscustomobject]@{ Success = $false; Value = [int64]0; Error = 'invalid' }
    }
    if ($parsed -lt 0) {
        return [pscustomobject]@{ Success = $false; Value = [int64]0; Error = 'negative' }
    }

    return [pscustomobject]@{ Success = $true; Value = $parsed; Error = $null }
}

function New-LunaCounterState {
    return [pscustomobject]@{
        SessionId   = $null
        HasBaseline = $false
        RxBytes     = [int64]0
        TxBytes     = [int64]0
        CapturedAt  = [DateTimeOffset]::MinValue
    }
}

function Update-LunaCounterState {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object]$State,
        [Parameter(Mandatory = $true)] [string]$SessionId,
        [Parameter(Mandatory = $true)] [object]$RxBytes,
        [Parameter(Mandatory = $true)] [object]$TxBytes,
        [Parameter(Mandatory = $true)] [DateTimeOffset]$CapturedAt
    )

    $rx = ConvertTo-LunaInt64Counter -Value $RxBytes
    $tx = ConvertTo-LunaInt64Counter -Value $TxBytes
    if (-not $rx.Success -or -not $tx.Success) {
        return [pscustomobject]@{
            Accepted = $false; IsBaseline = $false; Reset = $false; Reason = 'invalid-counter'
            RxBytes = [int64]0; TxBytes = [int64]0; RxDelta = [int64]0; TxDelta = [int64]0
            DownloadBytesPerSecond = [double]0; UploadBytesPerSecond = [double]0
        }
    }

    $reason = $null
    if (-not $State.HasBaseline) {
        $reason = 'initial-baseline'
    }
    elseif ($State.SessionId -ne $SessionId) {
        $reason = 'session-change'
    }
    elseif ($rx.Value -lt $State.RxBytes -or $tx.Value -lt $State.TxBytes) {
        $reason = 'counter-reset'
    }

    if ($null -ne $reason) {
        $State.SessionId = $SessionId
        $State.HasBaseline = $true
        $State.RxBytes = [int64]$rx.Value
        $State.TxBytes = [int64]$tx.Value
        $State.CapturedAt = $CapturedAt
        return [pscustomobject]@{
            Accepted = $true; IsBaseline = $true; Reset = ($reason -ne 'initial-baseline'); Reason = $reason
            RxBytes = [int64]$rx.Value; TxBytes = [int64]$tx.Value; RxDelta = [int64]0; TxDelta = [int64]0
            DownloadBytesPerSecond = [double]0; UploadBytesPerSecond = [double]0
        }
    }

    $seconds = ($CapturedAt - $State.CapturedAt).TotalSeconds
    if ($seconds -le 0) {
        return [pscustomobject]@{
            Accepted = $false; IsBaseline = $false; Reset = $false; Reason = 'non-monotonic-time'
            RxBytes = [int64]$rx.Value; TxBytes = [int64]$tx.Value; RxDelta = [int64]0; TxDelta = [int64]0
            DownloadBytesPerSecond = [double]0; UploadBytesPerSecond = [double]0
        }
    }

    $rxDelta = [int64]($rx.Value - $State.RxBytes)
    $txDelta = [int64]($tx.Value - $State.TxBytes)
    $downRate = [double]$rxDelta / [double]$seconds
    $upRate = [double]$txDelta / [double]$seconds

    $State.RxBytes = [int64]$rx.Value
    $State.TxBytes = [int64]$tx.Value
    $State.CapturedAt = $CapturedAt

    return [pscustomobject]@{
        Accepted = $true; IsBaseline = $false; Reset = $false; Reason = 'delta'
        RxBytes = [int64]$rx.Value; TxBytes = [int64]$tx.Value
        RxDelta = $rxDelta; TxDelta = $txDelta
        DownloadBytesPerSecond = $downRate; UploadBytesPerSecond = $upRate
    }
}

function New-LunaBoundedQueue {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [ValidateRange(1, 1000000)] [int]$Capacity)

    return [pscustomobject]@{
        Capacity = $Capacity
        Items = New-Object 'System.Collections.Generic.Queue[object]'
        Dropped = [int64]0
    }
}

function Add-LunaBoundedQueueItem {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object]$Queue,
        [Parameter(Mandatory = $true)] [AllowNull()] [object]$Item
    )

    while ($Queue.Items.Count -ge $Queue.Capacity) {
        $null = $Queue.Items.Dequeue()
        $Queue.Dropped = [int64]($Queue.Dropped + 1)
    }
    $Queue.Items.Enqueue($Item)
}

function Take-LunaBoundedQueueBatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)] [object]$Queue,
        [Parameter(Mandatory = $true)] [ValidateRange(1, 10000)] [int]$MaxCount
    )

    $count = [Math]::Min($MaxCount, $Queue.Items.Count)
    $result = New-Object 'System.Collections.Generic.List[object]'
    for ($i = 0; $i -lt $count; $i++) {
        $result.Add($Queue.Items.Dequeue())
    }
    return $result.ToArray()
}

function ConvertTo-LunaTelemetryCounterString {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [object]$Value)

    $parsed = ConvertTo-LunaInt64Counter -Value $Value
    if (-not $parsed.Success) {
        throw "Invalid telemetry counter: $($parsed.Error)"
    }
    return $parsed.Value.ToString([Globalization.CultureInfo]::InvariantCulture)
}

function Format-LunaDuration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)] [TimeSpan]$Duration)

    if ($Duration -lt [TimeSpan]::Zero) {
        $Duration = [TimeSpan]::Zero
    }
    $hours = [Math]::Floor($Duration.TotalHours)
    return ('{0:00}:{1:00}:{2:00}' -f $hours, $Duration.Minutes, $Duration.Seconds)
}

Export-ModuleMember -Function ConvertTo-LunaInt64Counter, New-LunaCounterState, Update-LunaCounterState, New-LunaBoundedQueue, Add-LunaBoundedQueueItem, Take-LunaBoundedQueueBatch, ConvertTo-LunaTelemetryCounterString, Format-LunaDuration
