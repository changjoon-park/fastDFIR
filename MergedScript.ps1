# Merged Script - Created 2024-12-09 00:05:51


#region Get-ADComputers.ps1

function Get-ADComputers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Computers",
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
        
        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $computers -ExportPath $ExportPath
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "Computer retrieval complete" -Completed
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}

#endregion


#region Get-ADDomainInfo.ps1

function Get-ADDomainInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$DomainNames
    )
    
    try {
        Write-Log "Retrieving AD domain information..." -Level Info
        
        $results = foreach ($domainName in $DomainNames) {
            try {
                Write-Log "Attempting to access domain: $domainName" -Level Info
                
                $domain = Invoke-WithRetry -ScriptBlock {
                    Get-ADDomain -Identity $domainName -ErrorAction Stop
                }

                # Try to get domain controllers
                $domainControllers = try {
                    Get-ADDomainController -Filter "Domain -eq '$domainName'" -ErrorAction Stop | 
                    ForEach-Object {
                        [PSCustomObject]@{
                            HostName               = $_.HostName
                            IPv4Address            = $_.IPv4Address
                            Site                   = $_.Site
                            IsGlobalCatalog        = $_.IsGlobalCatalog
                            OperatingSystem        = $_.OperatingSystem
                            OperatingSystemVersion = $_.OperatingSystemVersion
                            Enabled                = $_.Enabled
                        }
                    }
                }
                catch {
                    Write-Log "Unable to retrieve domain controllers for $domainName : $($_.Exception.Message)" -Level Warning
                    "Access Denied or Connection Failed"
                }

                [PSCustomObject]@{
                    DomainName           = $domainName
                    DomainMode           = $domain.DomainMode
                    PDCEmulator          = $domain.PDCEmulator
                    RIDMaster            = $domain.RIDMaster
                    InfrastructureMaster = $domain.InfrastructureMaster
                    DomainControllers    = $domainControllers
                    AccessStatus         = "Success"
                }
            }
            catch {
                Write-Log "Failed to access domain $domainName : $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    DomainName           = $domainName
                    DomainMode           = $null
                    PDCEmulator          = $null
                    RIDMaster            = $null
                    InfrastructureMaster = $null
                    DomainControllers    = @()
                    AccessStatus         = "Access Failed: $($_.Exception.Message)"
                }
            }
        }

        return $results
    }
    catch {
        Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADGroupsAndMembers.ps1

function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Groups",
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

        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $groupObjects -ExportPath $ExportPath
        
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

#endregion


#region Get-ADSiteInfo.ps1

function Get-ADSiteInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving AD site information..." -Level Info
        
        Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $site = $_
            $subnets = Get-ADReplicationSubnet -Filter * -ErrorAction SilentlyContinue | 
            Where-Object { $_.Site -eq $site.DistinguishedName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Site        = $_.Site
                    Location    = $_.Location
                    Description = $_.Description
                }
            }

            $siteLinks = Get-ADReplicationSiteLink -Filter * -ErrorAction SilentlyContinue |
            Where-Object { $_.Sites -contains $site.DistinguishedName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name                          = $_.Name
                    Cost                          = $_.Cost
                    ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
                    Sites                         = $_.Sites
                }
            }

            [PSCustomObject]@{
                SiteName    = $site.Name
                Description = $site.Description
                Location    = $site.Location
                Subnets     = $subnets
                SiteLinks   = $siteLinks
                Created     = $site.Created
                Modified    = $site.Modified
            }
        }
    }
    catch {
        Write-Log "Error retrieving site information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADTrustInfo.ps1

function Get-ADTrustInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootDomain
    )
    
    try {
        Write-Log "Retrieving AD trust information..." -Level Info
        
        Get-ADTrust -Filter * -Server $RootDomain -ErrorAction SilentlyContinue | 
        ForEach-Object {
            [PSCustomObject]@{
                Name      = $_.Name
                Source    = $_.Source
                Target    = $_.Target
                TrustType = $_.TrustType
                Direction = $_.Direction
                TGTQuota  = $_.TGTQuota
                Status    = try {
                    Test-ADTrust -Identity $_.Name -ErrorAction Stop
                    "Valid"
                }
                catch {
                    "Invalid: $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADUsers.ps1

function Get-ADUsers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Users",
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
            'DistinguishedName'
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                [PSCustomObject]@{
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $user.DisplayName
                    EmailAddress         = $user.EmailAddress
                    Enabled              = $user.Enabled
                    LastLogonDate        = $user.LastLogonDate
                    PasswordLastSet      = $user.PasswordLastSet
                    PasswordNeverExpires = $user.PasswordNeverExpires
                    PasswordExpired      = $user.PasswordExpired
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
                    DistinguishedName    = $null
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $users -ExportPath $ExportPath 
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "User retrieval complete" -Completed
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}

#endregion


#region Get-DomainInventory.ps1

function Get-DomainInventory {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath,
        [Parameter()]
        [ValidateSet("JSON", "CSV")]
        [string]$ExportType = "JSON", # Default export type is JSON
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
        
        $currentStep++
        
        # Run selected components
        if (-not $SkipUsers) {
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing Users" `
                -PercentComplete (($currentStep / $totalSteps) * 100)
            
            Get-ADUsers -ExportPath $ExportPath | Out-Null
            $currentStep++
        }
        
        if (-not $SkipComputers) {
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing Computers" `
                -PercentComplete (($currentStep / $totalSteps) * 100)
            
            Get-ADComputers -ExportPath $ExportPath | Out-Null
            $currentStep++
        }
        
        if (-not $SkipGroups) {
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing Groups" `
                -PercentComplete (($currentStep / $totalSteps) * 100)
            
            Get-ADGroupsAndMembers -ExportPath $ExportPath | Out-Null
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

#endregion


#region Get-ForestInventory.ps1

function Get-ForestInventory {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "ForestInfo",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving comprehensive forest information..." -Level Info

        $forest = Invoke-WithRetry -ScriptBlock {
            Get-ADForest -ErrorAction Stop
        }

        $forestInfo = [PSCustomObject]@{
            ForestRootDomain   = $forest.RootDomain
            ForestMode         = $forest.ForestMode
            GlobalCatalogs     = $forest.GlobalCatalogs
            Domains            = $forest.Domains
            SchemaMaster       = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
        }

        # Get detailed information using the separate functions
        $trustInfo = Get-ADTrustInfo -RootDomain $forest.RootDomain
        $domainInfo = Get-ADDomainInfo -DomainNames $forest.Domains
        $siteInfo = Get-ADSiteInfo

        # Add the detailed information to the forest object
        $forestInfo | Add-Member -MemberType NoteProperty -Name Trusts -Value $trustInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name DomainInfo -Value $domainInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name Sites -Value $siteInfo

        Export-ADData -ObjectType $ObjectType -Data $forestInfo -ExportPath $ExportPath

        return $forestInfo
    }
    catch {
        Write-Log "Failed to retrieve forest information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve forest info."
        return $null
    }
}

#endregion


#region Export-ADData.ps1

function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectType,
        
        [Parameter(Mandatory = $true)]
        [object]$Data, # Changed from IEnumerable to object
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )

    # Verify the export format is JSON
    if ($script:Config.DefaultExportFormat -ne "JSON") {
        Write-Log "Invalid export format specified in configuration. Defaulting to JSON." -Level Warning
    }
    
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }
    
    $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
    $exportFile = Join-Path $ExportPath ("{0}_{1}.json" -f $ObjectType, $timestamp)
    
    # If $Data is not an array, just wrap it in one before converting to JSON
    if ($Data -isnot [System.Collections.IEnumerable] -or $Data -is [string]) {
        $Data = @($Data)
    }
    
    $Data | ConvertTo-Json -Depth 10 | Out-File $exportFile
    
    $fullPath = (Resolve-Path $exportFile).Path
    Write-Log "$ObjectType exported to $fullPath" -Level Info
}

#endregion


#region Get-ADObjects.ps1

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

#endregion


#region Get-CollectionStatistics.ps1

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

#endregion


#region Import-ADModule.ps1

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

#endregion


#region Initialize-Environment.ps1

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

#endregion


#region Invoke-WithRetry.ps1

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

#endregion


#region Show-ErrorBox.ps1

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

#endregion


#region Show-ProgressHelper.ps1

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

#endregion


#region Write-Log.ps1

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

#endregion

