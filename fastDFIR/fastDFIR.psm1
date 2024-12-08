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

# Check and import ActiveDirectory module first
try {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "ActiveDirectory module imported successfully" -ForegroundColor Green
    }
}
catch [System.IO.FileNotFoundException] {
    Write-Error "ActiveDirectory module not found. Please install RSAT tools or enable the Active Directory PowerShell features."
    return
}
catch {
    Write-Error "Failed to import ActiveDirectory module: $($_.Exception.Message)"
    return
}

# Import all private functions
Get-ChildItem -Path "$PSScriptRoot\Private\*.ps1" | ForEach-Object {
    . $_.FullName
}

# Import all public functions
Get-ChildItem -Path "$PSScriptRoot\Public\*.ps1" | ForEach-Object {
    . $_.FullName
}