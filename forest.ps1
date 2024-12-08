# Script Configuration
$script:Config = @{
    ExportPath          = ".\Reports"
    LogPath             = ".\Logs"
    MaxConcurrentJobs   = 5
    RetryAttempts       = 3
    RetryDelaySeconds   = 5
    DefaultExportFormat = "CSV" # Can be CSV, JSON, or HTML
    VerboseOutput       = $false
    MaxQueryResults     = 10000
}

# Add required assembly for message boxes
Add-Type -AssemblyName System.Windows.Forms

#region Utility Functions
function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info',
        [string]$LogPath = (Join-Path $script:Config.LogPath "ADInventory.log")
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "$timestamp [$Level] $Message"
    
    # Ensure log directory exists
    if (-not (Test-Path (Split-Path $LogPath))) {
        New-Item -ItemType Directory -Path (Split-Path $LogPath) -Force
    }
    
    # Write to log file
    Add-Content -Path $LogPath -Value $logMessage
    
    # Also write to console with appropriate color
    switch ($Level) {
        'Error' { Write-Host $logMessage -ForegroundColor Red }
        'Warning' { Write-Host $logMessage -ForegroundColor Yellow }
        'Info' { Write-Host $logMessage -ForegroundColor Green }
    }
}

function Show-ErrorBox {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )

    [System.Windows.Forms.MessageBox]::Show($Message, "Permission or Error Issue", 
        [System.Windows.Forms.MessageBoxButtons]::OK, 
        [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
    
    Write-Log $Message -Level Error
}

function Invoke-WithRetry {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [scriptblock]$ScriptBlock,
        [int]$RetryCount = $script:Config.RetryAttempts,
        [int]$RetryDelaySeconds = $script:Config.RetryDelaySeconds
    )
    
    $attempt = 1
    do {
        try {
            return & $ScriptBlock
        }
        catch {
            if ($attempt -eq $RetryCount) {
                throw
            }
            Write-Log "Attempt $attempt failed. Retrying in $RetryDelaySeconds seconds..." -Level Warning
            Start-Sleep -Seconds $RetryDelaySeconds
            $attempt++
        }
    } while ($attempt -le $RetryCount)
}

function Initialize-Environment {
    [CmdletBinding()]
    param()
    
    try {
        # Create necessary directories
        @($script:Config.ExportPath, $script:Config.LogPath) | ForEach-Object {
            if (-not (Test-Path $_)) {
                New-Item -ItemType Directory -Path $_ -Force
                Write-Log "Created directory: $_" -Level Info
            }
        }
        
        # Test write permissions
        $testFile = Join-Path $script:Config.ExportPath "test.txt"
        try {
            [void](New-Item -ItemType File -Path $testFile -Force)
            Remove-Item $testFile -Force
            Write-Log "Write permissions verified" -Level Info
        }
        catch {
            throw "No write permission in export directory"
        }
        
        return $true
    }
    catch {
        Write-Log "Failed to initialize environment: $($_.Exception.Message)" -Level Error
        return $false
    }
}
#endregion

function Show-ProgressHelper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]  # Add validation
        [string]$Activity = "Processing", # Add default value even though it's mandatory
        [string]$Status = "Processing...",
        [int]$PercentComplete = -1,
        [string]$CurrentOperation = "",
        [switch]$Completed
    )
    
    # Additional validation
    if ([string]::IsNullOrWhiteSpace($Activity)) {
        $Activity = "Processing"  # Fallback value
    }
    
    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
    }
    else {
        $progressParams = @{
            Activity = $Activity
            Status   = $Status
        }
        
        if ($PercentComplete -ge 0) {
            $progressParams['PercentComplete'] = $PercentComplete
        }
        
        if (![string]::IsNullOrWhiteSpace($CurrentOperation)) {
            $progressParams['CurrentOperation'] = $CurrentOperation
        }
        
        Write-Progress @progressParams
    }
}

# And ensure all calls to Show-ProgressHelper have a valid Activity parameter
function Process-ADObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectType,
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Objects,
        [Parameter(Mandatory)]
        [scriptblock]$ProcessingScript
    )
    
    $totalCount = ($Objects | Measure-Object).Count
    $counter = 0
    $results = @()
    
    foreach ($object in $Objects) {
        $counter++
        $percentComplete = ($counter / $totalCount) * 100
        
        $currentItem = switch ($ObjectType) {
            "Users" { $object.SamAccountName }
            "Computers" { $object.Name }
            "Groups" { $object.Name }
            default { "Item $counter" }
        }
        
        $activityName = "Processing $ObjectType"  # Ensure this is never null
        $statusMessage = "Processing item $counter of $totalCount"
        
        Show-ProgressHelper `
            -Activity $activityName `
            -Status $statusMessage `
            -CurrentOperation $currentItem `
            -PercentComplete $percentComplete
        
        $results += & $ProcessingScript $object
    }
    
    Show-ProgressHelper -Activity "Processing $ObjectType" -Status "Complete" -Completed
    return $results
}

#region Core AD Functions
function Import-ADModule {
    [CmdletBinding()]
    param()
    
    try {
        if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
            Import-Module ActiveDirectory -ErrorAction Stop
            Write-Log "ActiveDirectory module imported successfully" -Level Info
        }
    }
    catch [System.IO.FileNotFoundException] {
        Write-Log "ActiveDirectory module not found. Please install RSAT tools." -Level Error
        Show-ErrorBox "ActiveDirectory module not found. Please install RSAT tools."
        return $false
    }
    catch {
        Write-Log "Failed to import ActiveDirectory module: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Failed to import ActiveDirectory module: $($_.Exception.Message)"
        return $false
    }
    return $true
}

function Get-ForestInfo {
    [CmdletBinding()]
    param()

    try {
        Write-Log "Retrieving forest information..." -Level Info
        $forest = Invoke-WithRetry -ScriptBlock {
            Get-ADForest -ErrorAction Stop
        }
        Write-Host "===== Forest Information ====="
        $forest
        return $forest
    }
    catch {
        Write-Log "Failed to retrieve forest information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve forest info."
    }
}

function Get-DomainInfo {
    [CmdletBinding()]
    param()

    try {
        Write-Log "Retrieving domain information..." -Level Info
        $domain = Invoke-WithRetry -ScriptBlock {
            Get-ADDomain -ErrorAction Stop
        }
        Write-Host "===== Domain Information ====="
        $domain
        return $domain
    }
    catch {
        Write-Log "Failed to retrieve domain information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve domain info."
    }
}

function Show-ProgressHelper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Activity,
        [Parameter(Mandatory)]
        [string]$Status,
        [int]$PercentComplete = -1,
        [string]$CurrentOperation = "",
        [switch]$Completed
    )
    
    if ($Completed) {
        Write-Progress -Activity $Activity -Completed
    }
    else {
        Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete -CurrentOperation $CurrentOperation
    }
}

function Process-ADObjects {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$ObjectType,
        [Parameter(Mandatory)]
        [System.Collections.IEnumerable]$Objects,
        [Parameter(Mandatory)]
        [scriptblock]$ProcessingScript
    )
    
    $totalCount = ($Objects | Measure-Object).Count
    $counter = 0
    $results = @()
    
    foreach ($object in $Objects) {
        $counter++
        $percentComplete = ($counter / $totalCount) * 100
        
        Show-ProgressHelper -Activity "Processing $ObjectType" `
            -Status "Processing $counter of $totalCount" `
            -CurrentOperation $object.Name `
            -PercentComplete $percentComplete
        
        $results += & $ProcessingScript $object
    }
    
    Show-ProgressHelper -Activity "Processing $ObjectType" -Completed
    return $results
}

function Get-ADUsers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$IncludeDisabled
    )
    
    try {
        Write-Log "Retrieving user accounts..." -Level Info
        # Make sure to provide both Activity and Status here
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing user retrieval..."
        
        $filter = if ($IncludeDisabled) { "*" } else { "Enabled -eq 'True'" }
        
        $properties = @(
            'SamAccountName',
            'DisplayName',
            'EmailAddress',
            'Enabled',
            'LastLogonDate',
            'PasswordLastSet',
            'PasswordNeverExpires',
            'PasswordExpired',
            'AccountExpirationDate'
        )
        
        # Make sure to provide both Activity and Status here
        Show-ProgressHelper -Activity "AD Inventory" -Status "Getting users..."
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Process-ADObjects -ObjectType "Users" -Objects $allUsers -ProcessingScript {
            param($user)
            $user | Select-Object $properties
        }
        
        if ($Export) {
            # Make sure to provide both Activity and Status here
            Show-ProgressHelper -Activity "AD Inventory" -Status "Exporting user data..."
            if (-not (Test-Path $ExportPath)) {
                New-Item -ItemType Directory -Path $ExportPath -Force
            }
            $exportFile = Join-Path $ExportPath "Users_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $users | Export-Csv $exportFile -NoTypeInformation
            Write-Log "Users exported to $exportFile" -Level Info
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "User retrieval complete" -Completed
        return $users
        
    }
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Log "Domain controller is not accessible" -Level Error
        Show-ErrorBox "Domain controller is not accessible. Please check network connectivity."
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}

# Main execution function
function Run-DomainInventory {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$SkipUsers,
        [switch]$SkipComputers,
        [switch]$SkipGroups,
        [switch]$Verbose
    )
    
    if (-not (Initialize-Environment)) {
        Write-Log "Environment initialization failed" -Level Error
        return
    }
    
    if (-not (Import-ADModule)) {
        Write-Log "AD Module import failed" -Level Error
        return
    }
    
    $startTime = Get-Date
    Write-Log "Starting AD Inventory at $startTime" -Level Info
    
    try {
        # Get Forest and Domain Info
        $forest = Get-ForestInfo
        $domain = Get-DomainInfo
        
        # Run selected components
        if (-not $SkipUsers) {
            Get-ADUsers -Export -ExportPath $ExportPath
        }
        
        if (-not $SkipComputers) {
            Get-ADComputers -Export -ExportPath $ExportPath
        }
        
        if (-not $SkipGroups) {
            Get-ADGroupsAndMembers -Export -ExportPath $ExportPath
        }
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        Write-Log "AD Inventory completed. Duration: $($duration.TotalMinutes) minutes" -Level Info
        
    }
    catch {
        Write-Log "Error during inventory: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error during inventory process"
    }
}

# Export functions for module use
Export-ModuleMember -Function @(
    'Run-DomainInventory',
    'Get-ForestInfo',
    'Get-DomainInfo',
    'Get-ADUsers'
)