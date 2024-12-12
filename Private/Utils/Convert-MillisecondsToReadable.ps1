function Convert-MillisecondsToReadable {
    param ([int64]$Milliseconds)
    $timespan = [TimeSpan]::FromMilliseconds($Milliseconds)
    return "$($timespan.Minutes) min $($timespan.Seconds) seconds"
}
