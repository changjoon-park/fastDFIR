# Merged Script - Created 2024-12-10 20:51:28


#region MergedScript.ps1

# Merged Script - Created 2024-12-10 20:51:28


#region MergedScript.ps1


#endregion


#region config.ps1

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

#endregion


#region Get-ADPolicyInfo.ps1

function Get-ADPolicyInfo {
    try {
        Write-Log "Retrieving AD policy information..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing policy retrieval..."

        # Get all GPOs
        $gpos = Get-GPO -All | ForEach-Object {
            $gpo = $_
            
            # Get GPO links
            $gpoLinks = Get-GPOLinks -GPO $gpo
            
            # Get detailed settings
            $report = Get-GPOReport -Guid $gpo.Id -ReportType XML
            [xml]$xmlReport = $report
            
            # Extract specific policy settings
            $passwordPolicy = Get-PasswordPolicyFromGPO -GPOReport $xmlReport
            $auditPolicy = Get-AuditPolicyFromGPO -GPOReport $xmlReport
            
            [PSCustomObject]@{
                Name             = $gpo.DisplayName
                ID               = $gpo.Id
                DomainName       = $gpo.DomainName
                CreationTime     = $gpo.CreationTime
                ModificationTime = $gpo.ModificationTime
                Status           = $gpo.GpoStatus
                Links            = $gpoLinks
                PasswordPolicies = $passwordPolicy
                AuditPolicies    = $auditPolicy
                ComputerEnabled  = $gpo.Computer.Enabled
                UserEnabled      = $gpo.User.Enabled
            }
        }

        # Get account lockout policies
        $lockoutPolicies = Get-ADDefaultDomainPasswordPolicy | ForEach-Object {
            [PSCustomObject]@{
                LockoutDuration          = $_.LockoutDuration
                LockoutObservationWindow = $_.LockoutObservationWindow
                LockoutThreshold         = $_.LockoutThreshold
                ComplexityEnabled        = $_.ComplexityEnabled
                MinPasswordLength        = $_.MinPasswordLength
                PasswordHistoryCount     = $_.PasswordHistoryCount
                MaxPasswordAge           = $_.MaxPasswordAge
                MinPasswordAge           = $_.MinPasswordAge
            }
        }

        # Get Fine-Grained Password Policies
        $fgppPolicies = Get-ADFineGrainedPasswordPolicy -Filter * | ForEach-Object {
            [PSCustomObject]@{
                Name                 = $_.Name
                Precedence           = $_.Precedence
                AppliesTo            = $_.AppliesTo
                LockoutDuration      = $_.LockoutDuration
                LockoutThreshold     = $_.LockoutThreshold
                ComplexityEnabled    = $_.ComplexityEnabled
                MinPasswordLength    = $_.MinPasswordLength
                PasswordHistoryCount = $_.PasswordHistoryCount
                MaxPasswordAge       = $_.MaxPasswordAge
                MinPasswordAge       = $_.MinPasswordAge
            }
        }

        $policyInfo = [PSCustomObject]@{
            GroupPolicies               = $gpos
            DefaultLockoutPolicy        = $lockoutPolicies
            FineGrainedPasswordPolicies = $fgppPolicies
        }

        return $policyInfo
    }
    catch {
        Write-Log "Error retrieving policy information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve policy information. Check permissions."
    }
}

# Helper function to get GPO links
function Get-GPOLinks {
    param (
        [Parameter(Mandatory)]
        $GPO
    )
    
    try {
        $links = (Get-GPOReport -Guid $GPO.Id -ReportType XML) -Replace "</?Report>|</?GPO>"
        [xml]$xmlLinks = "<Root>$links</Root>"
        
        $xmlLinks.Root.LinksTo | ForEach-Object {
            [PSCustomObject]@{
                Location   = $_.SOMPath
                Enabled    = $_.Enabled
                NoOverride = $_.NoOverride
                Type       = switch -Regex ($_.SOMPath) {
                    '^[^/]+$' { 'Domain' }
                    'OU=' { 'OU' }
                    'CN=Sites' { 'Site' }
                    default { 'Unknown' }
                }
            }
        }
    }
    catch {
        Write-Log "Error getting GPO links for $($GPO.DisplayName): $($_.Exception.Message)" -Level Warning
        return $null
    }
}

# Helper function to extract password policies from GPO
function Get-PasswordPolicyFromGPO {
    param(
        [Parameter(Mandatory)]
        [xml]$GPOReport
    )
    
    try {
        $passwordPolicies = $GPOReport.SelectNodes("//SecurityOptions/SecurityOption[contains(Name, 'Password')]")
        
        $passwordPolicies | ForEach-Object {
            [PSCustomObject]@{
                Setting = $_.Name
                State   = $_.State
                Value   = $_.SettingNumber
            }
        }
    }
    catch {
        Write-Log "Error extracting password policies: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

# Helper function to extract audit policies from GPO
function Get-AuditPolicyFromGPO {
    param(
        [Parameter(Mandatory)]
        [xml]$GPOReport
    )
    
    try {
        $auditPolicies = $GPOReport.SelectNodes("//AuditSetting")
        
        $auditPolicies | ForEach-Object {
            [PSCustomObject]@{
                Category     = $_.SubcategoryName
                AuditSuccess = $_.SettingValue -band 1
                AuditFailure = $_.SettingValue -band 2
            }
        }
    }
    catch {
        Write-Log "Error extracting audit policies: $($_.Exception.Message)" -Level Warning
        return $null
    }
}

#endregion


#region Get-ADSecurityConfiguration.ps1

function Get-ADSecurityConfiguration {
    try {
        Write-Log "Retrieving AD security configuration..." -Level Info

        $securityConfig = [PSCustomObject]@{
            ObjectACLs       = Get-CriticalObjectACLs
            FileShareACLs    = Get-CriticalShareACLs
            SPNConfiguration = Get-SPNConfiguration
        }
        
        return $securityConfig
    }
    catch {
        Write-Log "Error retrieving security configuration: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve security configuration. Check permissions."
    }
}

function Get-CriticalObjectACLs {
    try {
        Write-Log "Collecting ACLs for critical AD objects..." -Level Info
        
        # Get all OUs
        $ous = Get-ADOrganizationalUnit -Filter *
        
        $acls = foreach ($ou in $ous) {
            try {
                $acl = Get-Acl -Path "AD:$ou"
                
                [PSCustomObject]@{
                    OU          = $ou.Name
                    Path        = $ou.path
                    Owner       = $acl.Owner
                    AccessRules = $acl.Access | ForEach-Object {
                        [PSCustomObject]@{
                            Principal  = $_.IdentityReference.Value
                            AccessType = $_.AccessControlType.ToString()
                            Rights     = $_.ActiveDirectoryRights.ToString()
                            Inherited  = $_.IsInherited
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting ACL for $path : $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $acls
    }
    catch {
        Write-Log "Error collecting critical object ACLs: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-CriticalShareACLs {
    try {
        Write-Log "Collecting ACLs for SYSVOL and NETLOGON shares..." -Level Info
        
        $dc = Get-ADDomainController
        $shares = @("SYSVOL", "NETLOGON")
        
        $shareAcls = foreach ($share in $shares) {
            try {
                $path = "\\$($dc.HostName)\$share"
                $acl = Get-Acl -Path $path
                
                [PSCustomObject]@{
                    ShareName   = $share
                    Path        = $path
                    Owner       = $acl.Owner
                    AccessRules = $acl.AccessRules | ForEach-Object {
                        [PSCustomObject]@{
                            Principal  = $_.IdentityReference.Value
                            AccessType = $_.AccessControlType.ToString()
                            Rights     = $_.FileSystemRights.ToString()
                            Inherited  = $_.IsInherited
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting ACL for $share : $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $shareAcls
    }
    catch {
        Write-Log "Error collecting share ACLs: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-SPNConfiguration {
    try {
        Write-Log "Collecting SPN configuration..." -Level Info
        
        # Get all user accounts with SPNs
        $spnUsers = Get-ADUser -Filter * -Properties ServicePrincipalNames |
        Where-Object { $_.ServicePrincipalNames.Count -gt 0 }
        
        $spnConfig = foreach ($user in $spnUsers) {
            [PSCustomObject]@{
                UserName    = $user.SamAccountName
                Enabled     = $user.Enabled
                SPNs        = $user.ServicePrincipalNames
                IsDuplicate = $false  # Will be checked later
            }
        }
        
        # Check for duplicate SPNs
        $allSpns = $spnUsers | ForEach-Object { $_.ServicePrincipalNames } | Where-Object { $_ }
        $duplicateSpns = $allSpns | Group-Object | Where-Object { $_.Count -gt 1 }
        
        foreach ($dupSpn in $duplicateSpns) {
            $spnConfig | Where-Object { $_.SPNs -contains $dupSpn.Name } | 
            ForEach-Object { $_.IsDuplicate = $true }
        }
        
        return $spnConfig
    }
    catch {
        Write-Log "Error collecting SPN configuration: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADDomainInfo.ps1

function Get-ADDomainInfo {
    try {
        Write-Log "Retrieving AD domain information..." -Level Info
    
        $domain = Invoke-WithRetry -ScriptBlock {
            Get-ADDomain -ErrorAction Stop
        }

        # Try to get domain controllers
        $domainControllers = try {
            Get-ADDomainController -Filter * -ErrorAction Stop | 
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
            Write-Log "Unable to retrieve domain controllers: $($_.Exception.Message)" -Level Warning
            "Access Denied or Connection Failed"
        }

        $domainInfo = [PSCustomObject]@{
            DomainName           = $domain.Name
            DomainMode           = $domain.DomainMode
            PDCEmulator          = $domain.PDCEmulator
            RIDMaster            = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            DomainControllers    = $domainControllers
            OrganizationalUnits  = Get-ADOUInfo
        }

        return $domainInfo
    }
    catch {
        Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-ADOUInfo {
    
    try {
        Write-Log "Retrieving OU information for domain:..." -Level Info
        
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * -ErrorAction Stop
        
        $ouInfo = foreach ($ou in $ous) {
            [PSCustomObject]@{
                Name              = $ou.Name
                DistinguishedName = $ou.DistinguishedName
                Description       = $ou.Description
                Created           = $ou.Created
                Modified          = $ou.Modified
                ChildOUs          = ($ou.DistinguishedName -split ',OU=' | Select-Object -Skip 1) -join ',OU='
            }
        }
        
        return $ouInfo
    }
    catch {
        Write-Log "Error retrieving OU information for: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADForestInfo.ps1

function Get-ADForestInfo {
    try {
        Write-Log "Retrieving AD forest information..." -Level Info
        
        $forestInfo = Get-ADForest -ErrorAction SilentlyContinue | 
        ForEach-Object {
            [PSCustomObject]@{
                Name                = $_.Name
                ForestMode          = $_.ForestMode
                SchemaMaster        = $_.SchemaMaster
                DomainNamingMaster  = $_.DomainNamingMaster
                GlobalCatalogs      = $_.GlobalCatalogs
                Sites               = $_.Sites
                Domains             = $_.Domains
                RootDomain          = $_.RootDomain
                SchemaNamingContext = $_.SchemaNamingContext
                DistinguishedName   = $_.DistinguishedName
            }
        }

        return $forestInfo
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
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
        
        # Get all sites
        $sites = Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $site = $_
            
            # Get subnets for this site
            $subnets = Get-ADReplicationSubnet -Filter "site -eq '$($site.DistinguishedName)'" | 
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Location    = $_.Location
                    Description = $_.Description
                }
            }
            
            # Create the site object with all information
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Created                = $site.Created
                Modified               = $site.Modified
                Subnets                = $subnets
                SiteLinks              = (Get-ADReplicationSiteLink -Filter *)
                ReplicationConnections = Get-ADReplicationConnection
                DistinguishedName      = $site.DistinguishedName
            }
        }

        # Create a summary object that includes overall topology information
        $siteTopology = [PSCustomObject]@{
            Sites                = $sites
            TotalSites           = ($sites | Measure-Object).Count
            TotalSubnets         = ($sites.Subnets | Measure-Object).Count
            TotalSiteLinks       = ($sites.SiteLinks | Sort-Object -Property Name -Unique | Measure-Object).Count
            TotalReplConnections = ($sites.ReplicationConnections | Measure-Object).Count
        }

        return $siteTopology
    }
    catch {
        Write-Log "Error retrieving site information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADTrustInfo.ps1

function Get-ADTrustInfo {
    try {
        Write-Log "Retrieving AD trust information..." -Level Info
        
        Get-ADTrust -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            [PSCustomObject]@{
                Name               = $_.Name
                Source             = $_.Source
                Target             = $_.Target
                TrustType          = $_.TrustType
                Direction          = $_.Direction
                DisallowTransivity = $_.DisallowTransivity
                InstraForest       = $_.InstraForest
                TGTQuota           = $_.TGTQuota
                DistinguishedName  = $_.DistinguishedName
            }
        }
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


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
            'OperatingSystemServicePack',
            'Enabled',
            'LastLogonDate',
            'Created',
            'Modified',
            'DNSHostName',
            'SID',
            'ServicePrincipalNames'  # Added for service detection
        )
        
        $computers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computerObjects = Get-ADObjects -ObjectType $ObjectType -Objects $computers -ProcessingScript {
            param($computer)
            
            try {
                [PSCustomObject]@{
                    # Basic AD Info
                    Name                   = $computer.Name
                    IPv4Address            = $computer.IPv4Address
                    DNSHostName            = $computer.DNSHostName
                    OperatingSystem        = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    Enabled                = $computer.Enabled
                    LastLogonDate          = $computer.LastLogonDate
                    Created                = $computer.Created
                    Modified               = $computer.Modified
                    DistinguishedName      = $computer.DistinguishedName
                    ServicePrincipalNames  = $computer.ServicePrincipalNames
                    AccessStatus           = "Success"
                }
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                   = $computer.Name
                    IPv4Address            = $null
                    DNSHostName            = $null
                    OperatingSystem        = $null
                    OperatingSystemVersion = $null
                    Enabled                = $null
                    LastLogonDate          = $null
                    Created                = $null
                    Modified               = $null
                    DistinguishedName      = $computer.DistinguishedName
                    ServicePrincipalNames  = $null
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        return $computerObjects
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
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
        
        $properties = @(
            'Name',
            'Description',
            'GroupCategory',
            'GroupScope',
            'Members',
            'MemberOf',
            'DistinguishedName',
            'Created',
            'Modified'
        )

        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $groupObjects = Get-ADObjects -ObjectType $ObjectType -Objects $groups -ProcessingScript {
            param($group)
            
            try {
                [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory  # Security or Distribution
                    GroupScope             = $group.GroupScope       # Universal, Global, DomainLocal
                    TotalNestedMemberCount = $group.Members.Count
                    Members                = $group.Members
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Success"
                }
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory
                    GroupScope             = $group.GroupScope
                    TotalNestedMemberCount = 0
                    Members                = @()
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }
            }
        }

        return $groupObjects
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve groups. Check permissions."
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
            'DistinguishedName',
            'MemberOf'
        )
        
        $users = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $userObjects = Get-ADObjects -ObjectType $ObjectType -Objects $users -ProcessingScript {
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
                    MemberOf             = $user.MemberOf
                    AccountStatus        = if ($user.Enabled) { 
                        if ($user.PasswordExpired) { "Expired" } else { "Active" }
                    }
                    else { "Disabled" }
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
                    DistinguishedName    = $user.DistinguishedName
                    SID                  = $null
                    DelegatedPermissions = @()
                    AccountStatus        = $null
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }
            }
        }

        return $userObjects
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve users. Check permissions."
    }
}

#endregion


#region Get-DomainReport.ps1

function Get-DomainReport {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath
    )

    try {
        # Basic Domain Information
        $basicInfo = [PSCustomObject]@{
            ForestInfo = Get-ADForestInfo
            TrustInfo  = Get-ADTrustInfo
            Sites      = Get-ADSiteInfo
            DomainInfo = Get-ADDomainInfo
        }

        # Domain Objects Information
        $domainObjects = [PSCustomObject]@{
            Users     = Get-ADUsers
            Computers = Get-ADComputers
            Groups    = Get-ADGroupsAndMembers
        }

        # Security Configuration
        $Security = [PSCustomObject]@{
            # Policies           = Get-ADPolicyInfo # TODO: Permission Denied
            SecurityConfig = Get-ADSecurityConfiguration
        }

        # Final combined object
        $domainReport = [PSCustomObject]@{
            CollectionTime   = Get-Date
            BasicInfo        = $basicInfo
            DomainObjects    = $domainObjects
            SecuritySettings = $Security
            # Statistics       = Get-CollectionStatistics -Data $domainObjects
        }

        # TODO: Implement Export-ADData function (Add-member to $domainReport)
        # Export-ADData -Data $domainReport -ExportPath $ExportPath

        return $domainReport
    }
    catch {
        Write-Log "Error in Get-DomainReport: $($_.Exception.Message)" -Level Error
        throw
    }
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


#region Export-ADData.ps1

function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Data, 
        
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
    $exportFile = Join-Path $ExportPath ("DomainInventory_{1}.json" -f $timestamp)
    
    # If $Data is not an array, just wrap it in one before converting to JSON
    if ($Data -isnot [System.Collections.IEnumerable] -or $Data -is [string]) {
        $Data = @($Data)
    }
    
    $Data | ConvertTo-Json -Depth 10 | Out-File $exportFile
    
    $fullPath = (Resolve-Path $exportFile).Path
    Write-Log "Domain Inventory exported to $fullPath" -Level Info
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
        
        # Write-Host "`nDistribution by OU:"
        # $this.OUDistribution.GetEnumerator() | Sort-Object Name | ForEach-Object {
        #     Write-Host ("  - {0,-50} : {1,5}" -f $_.Key, $_.Value)
        # }
    }
    
    return $stats
}

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

