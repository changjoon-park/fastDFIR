function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectType, # e.g. "Users", "Groups", "Computers"
        
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Data, # The collection of objects to export
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath, # The directory to store the CSV
         
        [switch]$Export  # Whether to actually perform the export
    )

    if ($Export) {
        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
        $exportFile = Join-Path $ExportPath ("{0}_{1}.csv" -f $ObjectType, $timestamp)
        $Data | Export-Csv $exportFile -NoTypeInformation
        Write-Log "$ObjectType exported to $exportFile" -Level Info
    }
}

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
        [Parameter(Mandatory)]
        [ValidateSet('Users', 'Groups', 'Computers')]
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
        [string]$ObjectType = "Computers",
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
        
        $computers = Get-ADObjects -ObjectType $ObjectType -Objects $allComputers -ProcessingScript {
            param($computer)
            
            try {
                [PSCustomObject]@{
                    Name                   = $computer.Name
                    OperatingSystem        = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    Enabled                = $computer.Enabled
                    LastLogonDate          = $computer.LastLogonDate
                    Created                = $computer.Created
                    Modified               = $computer.Modified
                    DNSHostName            = $computer.DNSHostName
                    DistinguishedName      = $computer.DistinguishedName
                    AccessStatus           = "Success"
                }
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                   = $computer.Name
                    OperatingSystem        = $null
                    OperatingSystemVersion = $null
                    Enabled                = $null
                    LastLogonDate          = $null
                    Created                = $null
                    Modified               = $null
                    DNSHostName            = $null
                    DistinguishedName      = $computer.DistinguishedName
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $computers -ExportPath $ExportPath -Export:$Export
        
        # Complete progress
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
        [string]$ObjectType = "Groups",
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving groups and members..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        # Retrieve all groups and their members in one go
        # Include the 'Members' property so we can count directly without extra queries

        $properties = @(
            'Name',
            'Description',
            'Created',
            'Modified',
            'memberOf',
            'GroupCategory',
            'GroupScope',
            'Members',
            'DistinguishedName'
        )

        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $totalGroups = ($groups | Measure-Object).Count
        Write-Log "Found $totalGroups groups to process" -Level Info
        
        $groupObjects = Get-ADObjects -ObjectType $ObjectType -Objects $groups -ProcessingScript {
            param($group)
            
            try {
                # Since we already have the Members property, just count it
                $memberCount = if ($group.Members) { $group.Members.Count } else { 0 }
                
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
        $stats = Get-CollectionStatistics -Data $groupObjects -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()

        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $groupObjects -ExportPath $ExportPath -Export:$Export
        
        # Complete progress
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
        [string]$ObjectType = "Users",
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
            'DistinguishedName',
            'MemberOf'  # Added MemberOf property
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                $groupMemberships = @($user.MemberOf | ForEach-Object {
                        try {
                            $groupDN = $_
                            $group = Get-ADGroup $groupDN -Properties Name -ErrorAction SilentlyContinue
                            if ($group) {
                                $group.Name
                            }
                            else {
                                Write-Log "Group not found: $groupDN" -Level Warning
                                "Unknown Group ($($groupDN.Split(',')[0]))"  # Returns just the CN part of the DN
                            }
                        }
                        catch {
                            Write-Log "Error resolving group $groupDN : $($_.Exception.Message)" -Level Warning
                            "Unresolved Group ($($groupDN.Split(',')[0]))"  # Returns just the CN part of the DN
                        }
                    })

                [PSCustomObject]@{
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $user.DisplayName
                    EmailAddress         = $user.EmailAddress
                    Enabled              = $user.Enabled
                    LastLogonDate        = $user.LastLogonDate
                    PasswordLastSet      = $user.PasswordLastSet
                    PasswordNeverExpires = $user.PasswordNeverExpires
                    PasswordExpired      = $user.PasswordExpired
                    GroupMemberships     = $groupMemberships  # Added group memberships
                    GroupCount           = $groupMemberships.Count  # Added count of groups
                    DistinguishedName    = $user.DistinguishedName
                    AccessStatus         = "Success"
                }
            }
            catch {
                Write-Log "Error processing user $($user.SamAccountName): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $null
                    EmailAddress         = $null
                    Enabled              = $null
                    LastLogonDate        = $null
                    PasswordLastSet      = $null
                    PasswordNeverExpires = $null
                    PasswordExpired      = $null
                    GroupMemberships     = @()  # Empty array for failed processing
                    GroupCount           = 0    # Zero for failed processing
                    DistinguishedName    = $null
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $users -ExportPath $ExportPath -Export:$Export
        
        # Complete progress
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
