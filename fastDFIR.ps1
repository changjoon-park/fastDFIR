function Get-ADObjects {
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
        
        $activityName = "Processing $ObjectType"  
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
function Get-CollectionStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Data,
        [string]$ObjectType,
        [switch]$IncludeAccessStatus
    )
    
    $stats = [PSCustomObject]@{
        ObjectType     = $ObjectType
        TotalCount     = $Data.Count
        OUDistribution = @{}
        SuccessCount   = if ($IncludeAccessStatus) { 
            ($Data | Where-Object { $_.AccessStatus -eq 'Success' }).Count 
        }
        else { 0 }
        ErrorCount     = if ($IncludeAccessStatus) { 
            ($Data | Where-Object { $_.AccessStatus -ne 'Success' }).Count 
        }
        else { 0 }
    }
    
    # Count objects per OU
    $Data | ForEach-Object {
        $ouPath = ($_.DistinguishedName -split ',(?=OU=)' | Where-Object { $_ -match '^OU=' }) -join ','
        if (-not $ouPath) { $ouPath = "No OU (Root)" }
        
        if ($stats.OUDistribution.ContainsKey($ouPath)) {
            $stats.OUDistribution[$ouPath]++
        }
        else {
            $stats.OUDistribution[$ouPath] = 1
        }
    }
    
    # Add DisplayStatistics method
    Add-Member -InputObject $stats -MemberType ScriptMethod -Name DisplayStatistics -Value {
        Write-Host "`n=== $($this.ObjectType) Collection Statistics ==="
        Write-Host "Total $($this.ObjectType): $($this.TotalCount)"
        
        if ($this.SuccessCount -gt 0 -or $this.ErrorCount -gt 0) {
            Write-Host "Successfully Processed: $($this.SuccessCount)"
            Write-Host "Errors: $($this.ErrorCount)"
        }
        
        Write-Host "`nDistribution by OU:"
        $this.OUDistribution.GetEnumerator() | Sort-Object Name | ForEach-Object {
            Write-Host ("  - {0,-50} : {1,5}" -f $_.Key, $_.Value)
        }
    }
    
    return $stats
}

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

function Show-ProgressHelper {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]  # Add validation
        [string]$Activity, # Add default value even though it's mandatory
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

function Write-Log {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $logEntry = "[{0:yyyy-MM-dd HH:mm:ss}] [{1}] {2}" -f (Get-Date), $Level, $Message
    Add-Content -Path $script:Config.LogFile -Value $logEntry
}

function Get-ADComputers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving computer accounts..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing computer retrieval..."
        
        $properties = @(
            'Name',
            'DistinguishedName',
            'OperatingSystem',
            'OperatingSystemVersion',
            'Enabled',
            'LastLogonDate',
            'Created',
            'Modified',
            'DNSHostName'
        )
        
        $allComputers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computers = Get-ADObjects -ObjectType "Computers" -Objects $allComputers -ProcessingScript {
            param($computer)
            $computer | Select-Object $properties
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType "Groups" -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        if ($Export) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -ItemType Directory -Path $ExportPath -Force
            }
            $exportFile = Join-Path $ExportPath "Computers_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $computers | Export-Csv $exportFile -NoTypeInformation
            Write-Log "Computers exported to $exportFile" -Level Info
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "Computer retrieval complete" -Completed
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}


function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving groups and members..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        # First get all groups with basic properties in one quick query
        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties Name, Description, Created, Modified, DistinguishedName, 
            memberOf, GroupCategory, GroupScope -ErrorAction Stop
        }
        
        $totalGroups = ($groups | Measure-Object).Count
        Write-Log "Found $totalGroups groups to process" -Level Info
        
        $groupObjects = Get-ADObjects -ObjectType "Groups" -Objects $groups -ProcessingScript {
            param($group)
            
            try {
                # Fast member count retrieval with timeout protection
                $memberCount = 0
                $members = "Not retrieved due to timeout"
                
                $memberJob = Start-Job -ScriptBlock {
                    param($groupDN)
                    (Get-ADGroup $groupDN -Properties Members).Members.Count
                } -ArgumentList $group.DistinguishedName
                
                # Only wait 5 seconds max for member count
                if (Wait-Job $memberJob -Timeout 5) {
                    $memberCount = Receive-Job $memberJob
                }
                Remove-Job $memberJob -Force -ErrorAction SilentlyContinue
                
                [PSCustomObject]@{
                    Name              = $group.Name
                    Description       = $group.Description
                    MemberCount       = $memberCount
                    GroupCategory     = $group.GroupCategory
                    GroupScope        = $group.GroupScope
                    Created           = $group.Created
                    Modified          = $group.Modified
                    DistinguishedName = $group.DistinguishedName
                    AccessStatus      = "Success"
                }
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name              = $group.Name
                    Description       = $group.Description
                    MemberCount       = 0
                    GroupCategory     = $group.GroupCategory
                    GroupScope        = $group.GroupScope
                    Created           = $group.Created
                    Modified          = $group.Modified
                    DistinguishedName = $group.DistinguishedName
                    AccessStatus      = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics using Get-CollectionStatistics
        $stats = Get-CollectionStatistics -Data $groupObjects -ObjectType "Groups" -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        if ($Export) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -ItemType Directory -Path $ExportPath -Force
            }
            $exportFile = Join-Path $ExportPath "Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $groupObjects | Export-Csv $exportFile -NoTypeInformation
            Write-Log "Groups exported to $exportFile" -Level Info
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "Group retrieval complete" -Completed
        return $groupObjects
        
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve groups. Check permissions."
        return $null
    }
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
            'AccountExpirationDate',
            'DistinguishedName'  # Added for OU tracking
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType "Users" -Objects $allUsers -ProcessingScript {
            param($user)
            $user | Select-Object $properties
        }

        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType "Groups" -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        if ($Export) {
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
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
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

function Get-DomainInventory {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$SkipUsers,
        [switch]$SkipComputers,
        [switch]$SkipGroups
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
        $totalSteps = 3
        $currentStep = 0
        
        # Get Forest and Domain Info
        Show-ProgressHelper -Activity "AD Inventory" `
            -Status "Getting Forest and Domain Info" `
            -PercentComplete (($currentStep / $totalSteps) * 100)
        
        Invoke-WithRetry -ScriptBlock {
            $forest = Get-ForestInfo
            $domain = Get-DomainInfo
        }
        
        $currentStep++
        
        # Run selected components
        if (-not $SkipUsers) {
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing Users" `
                -PercentComplete (($currentStep / $totalSteps) * 100)
            
            Get-ADUsers -Export -ExportPath $ExportPath | Out-Null
            $currentStep++
        }
        
        if (-not $SkipComputers) {
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing Computers" `
                -PercentComplete (($currentStep / $totalSteps) * 100)
            
            Get-ADComputers -Export -ExportPath $ExportPath | Out-Null
            $currentStep++
        }
        
        if (-not $SkipGroups) {
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing Groups" `
                -PercentComplete (($currentStep / $totalSteps) * 100)
            
            Get-ADGroupsAndMembers -Export -ExportPath $ExportPath | Out-Null
            $currentStep++
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "Complete" -Completed
        
        $endTime = Get-Date
        $duration = $endTime - $startTime
        Write-Log "AD Inventory completed. Duration: $($duration.TotalMinutes) minutes" -Level Info
        
    }
    catch {
        Write-Log "Error during inventory: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error during inventory process"
    }
}
