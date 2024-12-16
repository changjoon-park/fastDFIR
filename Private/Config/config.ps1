# Import configuration
$script:Config = @{
    ExportPath          = ".\Reports"
    LogPath             = ".\Logs"
    MaxConcurrentJobs   = 5
    RetryAttempts       = 3
    RetryDelaySeconds   = 5
    DefaultExportFormat = "JSON"
    VerboseOutput       = $false
    MaxQueryResults     = 10000
}

