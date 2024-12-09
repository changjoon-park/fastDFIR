# Merged Script - Created 2024-12-09 02:12:16


#region MergedScript.ps1

# Merged Script - Created 2024-12-09 02:12:16


#region MergedScript.ps1


#endregion


#region mergeScript.ps1

$SourceDirectory = "."
$OutputFile = ".\MergedScript.ps1"

# Create or clear the output file
Set-Content -Path $OutputFile -Value "# Merged Script - Created $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Get all ps1 files recursively
$files = Get-ChildItem -Path $SourceDirectory -Filter "*.ps1" -Recurse

foreach ($file in $files) {
    # Add a header comment for each file
    Add-Content -Path $OutputFile -Value "`n#region $($file.Name)`n"
    
    # Get the content and add it to the merged file
    $content = Get-Content -Path $file.FullName
    Add-Content -Path $OutputFile -Value $content
    
    # Add an end region marker
    Add-Content -Path $OutputFile -Value "`n#endregion`n"
}

Write-Host "Merged $($files.Count) files into $OutputFile"

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
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Policies",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
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

        # Export data
        Export-ADData -ObjectType $ObjectType -Data $policyInfo -ExportPath $ExportPath

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
    [CmdletBinding()]
    param(
        [string]$ObjectType = "SecurityConfig",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving AD security configuration..." -Level Info

        $securityConfig = [PSCustomObject]@{
            ObjectACLs       = Get-CriticalObjectACLs
            FileShareACLs    = Get-CriticalShareACLs
            SPNConfiguration = Get-SPNConfiguration
            KerberosSettings = Get-KerberosConfiguration
        }

        # Export data
        Export-ADData -ObjectType $ObjectType -Data $securityConfig -ExportPath $ExportPath
        
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
        
        # Get domain root
        $domain = Get-ADDomain
        
        # Critical paths to check
        $criticalPaths = @(
            $domain.DistinguishedName, # Domain root
            "CN=Users,$($domain.DistinguishedName)", # Users container
            "CN=Computers,$($domain.DistinguishedName)", # Computers container
            "CN=System,$($domain.DistinguishedName)"      # System container
        )
        
        # Get all OUs
        $ous = Get-ADOrganizationalUnit -Filter *
        $criticalPaths += $ous.DistinguishedName
        
        $acls = foreach ($path in $criticalPaths) {
            try {
                $acl = Get-Acl -Path "AD:$path"
                
                [PSCustomObject]@{
                    Path        = $path
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
                    AccessRules = $acl.Access | ForEach-Object {
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

function Get-KerberosConfiguration {
    try {
        Write-Log "Collecting Kerberos configuration..." -Level Info
        
        # Get domain controller
        $dc = Get-ADDomainController
        
        # Get Kerberos policy
        $kerbPolicy = Get-GPObject -Name "Default Domain Policy" | 
        Get-GPOReport -ReportType Xml | 
        Select-Xml -XPath "//SecurityOptions/SecurityOption[contains(Name, 'Kerberos')]"
        
        # Get additional Kerberos settings from registry
        $regSettings = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        }
        
        return [PSCustomObject]@{
            MaxTicketAge              = $regSettings.MaxTicketAge
            MaxRenewAge               = $regSettings.MaxRenewAge
            MaxServiceAge             = $regSettings.MaxServiceAge
            MaxClockSkew              = $regSettings.MaxClockSkew
            PreAuthenticationRequired = $kerbPolicy.Node.SettingBoolean
            PolicySettings            = $kerbPolicy | ForEach-Object {
                [PSCustomObject]@{
                    Setting = $_.Node.Name
                    State   = $_.Node.State
                    Value   = $_.Node.SettingNumber
                }
            }
        }
    }
    catch {
        Write-Log "Error collecting Kerberos configuration: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADDNSInfo.ps1

function Get-ADDNSInfo {
    [CmdletBinding()]
    param()
    
    try {
        $dnsServer = Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName
        
        # Get all DNS zones
        $zones = Get-DnsServerZone -ComputerName $dnsServer | ForEach-Object {
            $zone = $_
            
            # Get all records for this zone
            $records = Get-DnsServerResourceRecord -ComputerName $dnsServer -ZoneName $zone.ZoneName |
            ForEach-Object {
                [PSCustomObject]@{
                    Name       = $_.HostName
                    RecordType = $_.RecordType
                    RecordData = $_.RecordData.IPv4Address ?? 
                    $_.RecordData.HostNameAlias ??
                    $_.RecordData.DomainName ??
                    $_.RecordData.StringData
                    Timestamp  = $_.Timestamp
                    TimeToLive = $_.TimeToLive
                }
            }
            
            # Special handling for SRV records
            $srvRecords = $records | Where-Object RecordType -eq 'SRV'
            
            [PSCustomObject]@{
                ZoneName               = $zone.ZoneName
                ZoneType               = $zone.ZoneType
                IsDsIntegrated         = $zone.IsDsIntegrated
                IsReverseLookupZone    = $zone.IsReverseLookupZone
                DynamicUpdate          = $zone.DynamicUpdate
                Records                = $records
                ServiceRecords         = $srvRecords
                ReplicationScope       = $zone.ReplicationScope
                DirectoryPartitionName = $zone.DirectoryPartitionName
            }
        }
        
        return [PSCustomObject]@{
            ForwardLookupZones = $zones | Where-Object { -not $_.IsReverseLookupZone }
            ReverseLookupZones = $zones | Where-Object IsReverseLookupZone
        }
    }
    catch {
        Write-Log "Error retrieving DNS information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADNetworkTopology.ps1

function Get-ADNetworkTopology {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "NetworkTopology",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving network topology information..." -Level Info
        
        # Get Sites and Subnets
        $siteInfo = Get-ADSiteTopology
        
        # Get DNS Zones
        $dnsInfo = Get-ADDNSInfo
        
        $networkTopology = [PSCustomObject]@{
            Sites    = $siteInfo
            DNSZones = $dnsInfo
        }
        
        # Export data
        Export-ADData -ObjectType $ObjectType -Data $networkTopology -ExportPath $ExportPath
        
        return $networkTopology
    }
    catch {
        Write-Log "Error retrieving network topology: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve network topology information. Check permissions."
    }
}

function Get-ADSiteTopology {
    [CmdletBinding()]
    param()
    
    try {
        $sites = Get-ADReplicationSite -Filter * | ForEach-Object {
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
            
            # Get site links
            $siteLinks = Get-ADReplicationSiteLink -Filter * |
            Where-Object { $_.Sites -contains $site.DistinguishedName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name                 = $_.Name
                    Cost                 = $_.Cost
                    ReplicationFrequency = $_.ReplicationFrequencyInMinutes
                    Schedule             = $_.ReplicationSchedule
                    Sites                = $_.Sites | ForEach-Object {
                        (Get-ADObject $_ -Properties Name).Name
                    }
                    Options              = $_.Options
                }
            }
            
            # Get replication connections
            $replConnections = Get-ADReplicationConnection -Filter "FromServer -like '*$($site.Name)*' -or ToServer -like '*$($site.Name)*'" |
            ForEach-Object {
                [PSCustomObject]@{
                    FromServer = $_.FromServer
                    ToServer   = $_.ToServer
                    Schedule   = $_.Schedule
                    Options    = $_.Options
                }
            }
            
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Subnets                = $subnets
                SiteLinks              = $siteLinks
                ReplicationConnections = $replConnections
            }
        }
        
        return $sites
    }
    catch {
        Write-Log "Error retrieving site topology: $($_.Exception.Message)" -Level Error
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
            'ServicePrincipalNames', # Added for role detection
            'Description',
            'Location',
            'primaryGroupID'          # To differentiate workstations/servers
        )
        
        $allComputers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computers = Get-ADObjects -ObjectType $ObjectType -Objects $allComputers -ProcessingScript {
            param($computer)
            
            try {
                # Determine computer type and roles
                $computerType = switch ($computer.primaryGroupID) {
                    515 { "Server" }
                    516 { "Workstation" }
                    default { "Unknown" }
                }

                # Parse SPNs to detect roles
                $roles = @()
                foreach ($spn in $computer.ServicePrincipalNames) {
                    switch -Regex ($spn) {
                        'DNS|host' { $roles += "DNS Server" }
                        'DHCP' { $roles += "DHCP Server" }
                        'CA' { $roles += "Certificate Authority" }
                        'MSSQL' { $roles += "SQL Server" }
                        'IISW3SVC' { $roles += "Web Server" }
                        'exchangeMDB' { $roles += "Exchange Server" }
                        'WSMAN' { $roles += "Windows Management" }
                        'FTP' { $roles += "FTP Server" }
                        'LDAP' { $roles += "Domain Controller" }
                        'RPCSS' { $roles += "RPC Server" }
                        'BITS' { $roles += "BITS Server" }
                    }
                }
                $roles = $roles | Select-Object -Unique

                # Check if it's a file server (attempt to get shares)
                if ($computerType -eq "Server") {
                    try {
                        $shares = Get-WmiObject -Class Win32_Share -ComputerName $computer.DNSHostName -ErrorAction Stop
                        if ($shares | Where-Object { $_.Type -eq 0 }) {
                            $roles += "File Server"
                        }
                    }
                    catch {
                        Write-Log "Unable to query shares on $($computer.Name): $($_.Exception.Message)" -Level Warning
                    }
                }

                # Get additional server features if possible
                if ($computerType -eq "Server") {
                    try {
                        $serverFeatures = Invoke-Command -ComputerName $computer.DNSHostName -ScriptBlock {
                            Get-WindowsFeature | Where-Object Installed
                        } -ErrorAction Stop
                        
                        foreach ($feature in $serverFeatures) {
                            $roles += "Windows Feature: $($feature.Name)"
                        }
                    }
                    catch {
                        Write-Log "Unable to query Windows features on $($computer.Name): $($_.Exception.Message)" -Level Warning
                    }
                }

                [PSCustomObject]@{
                    Name                       = $computer.Name
                    DNSHostName                = $computer.DNSHostName
                    ComputerType               = $computerType
                    OperatingSystem            = $computer.OperatingSystem
                    OperatingSystemVersion     = $computer.OperatingSystemVersion
                    OperatingSystemServicePack = $computer.OperatingSystemServicePack
                    Roles                      = $roles
                    Enabled                    = $computer.Enabled
                    LastLogonDate              = $computer.LastLogonDate
                    Created                    = $computer.Created
                    Modified                   = $computer.Modified
                    Description                = $computer.Description
                    Location                   = $computer.Location
                    DistinguishedName          = $computer.DistinguishedName
                    DomainJoined               = $true  # If it's in AD, it's domain-joined
                    AccessStatus               = "Success"
                }
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                       = $computer.Name
                    DNSHostName                = $null
                    ComputerType               = "Unknown"
                    OperatingSystem            = $null
                    OperatingSystemVersion     = $null
                    OperatingSystemServicePack = $null
                    Roles                      = @()
                    Enabled                    = $null
                    LastLogonDate              = $null
                    Created                    = $null
                    Modified                   = $null
                    Description                = $null
                    Location                   = $null
                    DistinguishedName          = $computer.DistinguishedName
                    DomainJoined               = $null
                    AccessStatus               = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $computers -ExportPath $ExportPath
        
        return $computers
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
            'AdminCount',
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
                # Get nested group membership recursively
                $allMembers = Get-ADGroupNestedMembers -Group $group
                
                # Determine if this is a privileged group
                $isPrivileged = $group.AdminCount -eq 1 -or 
                $group.Name -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')

                [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory  # Security or Distribution
                    GroupScope             = $group.GroupScope       # Universal, Global, DomainLocal
                    IsPrivileged           = $isPrivileged
                    DirectMemberCount      = ($group.Members | Measure-Object).Count
                    TotalNestedMemberCount = ($allMembers | Measure-Object).Count
                    Members                = $allMembers | ForEach-Object {
                        [PSCustomObject]@{
                            Name              = $_.Name
                            ObjectClass       = $_.ObjectClass
                            DistinguishedName = $_.DistinguishedName
                            MemberType        = if ($_.ObjectClass -eq 'group') { 'NestedGroup' } else { 'DirectMember' }
                        }
                    }
                    ParentGroups           = $group.MemberOf | ForEach-Object {
                        Get-ADGroup $_ | Select-Object -ExpandProperty Name
                    }
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
                    IsPrivileged           = $false
                    DirectMemberCount      = 0
                    TotalNestedMemberCount = 0
                    Members                = @()
                    ParentGroups           = @()
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

# Helper function to get nested group members recursively
function Get-ADGroupNestedMembers {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,
        [System.Collections.ArrayList]$ProcessedGroups = @()
    )
    
    if ($ProcessedGroups -contains $Group.DistinguishedName) {
        return @()
    }
    
    [void]$ProcessedGroups.Add($Group.DistinguishedName)
    
    $members = foreach ($member in $Group.Members) {
        $obj = Get-ADObject $member -Properties objectClass, name, distinguishedName
        
        if ($obj.objectClass -eq 'group') {
            $obj
            Get-ADGroupNestedMembers -Group (Get-ADGroup $obj -Properties Members) -ProcessedGroups $ProcessedGroups
        }
        else {
            $obj
        }
    }
    
    return $members
}

#endregion


#region Get-ADOUInfo.ps1

function Get-ADOUInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    
    try {
        Write-Log "Retrieving OU information for domain: $DomainName..." -Level Info
        
        $ous = Get-ADOrganizationalUnit -Filter * -Server $DomainName -Properties * -ErrorAction Stop
        
        $ouInfo = foreach ($ou in $ous) {
            # Get ACL information
            $acl = Get-Acl -Path "AD:$($ou.DistinguishedName)" -ErrorAction SilentlyContinue
            
            # Process permissions
            $permissions = $acl.Access | ForEach-Object {
                [PSCustomObject]@{
                    IdentityReference     = $_.IdentityReference.ToString()
                    AccessControlType     = $_.AccessControlType.ToString()
                    ActiveDirectoryRights = $_.ActiveDirectoryRights.ToString()
                    InheritanceType       = $_.InheritanceType.ToString()
                }
            }
            
            [PSCustomObject]@{
                Name                 = $ou.Name
                DistinguishedName    = $ou.DistinguishedName
                Description          = $ou.Description
                Created              = $ou.Created
                Modified             = $ou.Modified
                ChildOUs             = ($ou.DistinguishedName -split ',OU=' | Select-Object -Skip 1) -join ',OU='
                DelegatedPermissions = $permissions
            }
        }
        
        return $ouInfo
    }
    catch {
        Write-Log "Error retrieving OU information for $DomainName : $($_.Exception.Message)" -Level Error
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
            'DistinguishedName',
            'MemberOf',
            'AdminCount', # Added for privileged account detection
            'UserAccountControl'  # Added for account status
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        # Get privileged groups for reference
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        )
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                # Check if user is privileged
                $isPrivileged = $false
                $privilegedGroupMemberships = @()
                foreach ($group in $user.MemberOf) {
                    $groupName = (Get-ADGroup $group).Name
                    if ($privilegedGroups -contains $groupName) {
                        $isPrivileged = $true
                        $privilegedGroupMemberships += $groupName
                    }
                }

                # Check for delegated permissions
                $delegatedPermissions = Get-ObjectDelegatedPermissions -Identity $user.DistinguishedName

                # Determine account type
                $accountType = switch -Regex ($user.DistinguishedName) {
                    'OU=Service Accounts,' { 'ServiceAccount' }
                    'CN=Managed Service Accounts,' { 'ManagedServiceAccount' }
                    default { 'UserAccount' }
                }

                [PSCustomObject]@{
                    SamAccountName             = $user.SamAccountName
                    DisplayName                = $user.DisplayName
                    EmailAddress               = $user.EmailAddress
                    Enabled                    = $user.Enabled
                    LastLogonDate              = $user.LastLogonDate
                    PasswordLastSet            = $user.PasswordLastSet
                    PasswordNeverExpires       = $user.PasswordNeverExpires
                    PasswordExpired            = $user.PasswordExpired
                    DistinguishedName          = $user.DistinguishedName
                    AccountType                = $accountType
                    IsPrivileged               = $isPrivileged
                    PrivilegedGroupMemberships = $privilegedGroupMemberships
                    DelegatedPermissions       = $delegatedPermissions
                    AdminCount                 = $user.AdminCount
                    AccountStatus              = if ($user.Enabled) { 
                        if ($user.PasswordExpired) { "Expired" } else { "Active" }
                    }
                    else { "Disabled" }
                    AccessStatus               = "Success"
                }
            }
            catch {
                Write-Log "Error processing user $($user.SamAccountName): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    SamAccountName             = $user.SamAccountName
                    DisplayName                = $null
                    EmailAddress               = $null
                    Enabled                    = $null
                    LastLogonDate              = $null
                    PasswordLastSet            = $null
                    PasswordNeverExpires       = $null
                    PasswordExpired            = $null
                    DistinguishedName          = $user.DistinguishedName
                    AccountType                = $null
                    IsPrivileged               = $null
                    PrivilegedGroupMemberships = @()
                    DelegatedPermissions       = @()
                    AdminCount                 = $null
                    AccountStatus              = $null
                    AccessStatus               = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve users. Check permissions."
    }
}

# Helper function to get delegated permissions
function Get-ObjectDelegatedPermissions {
    param(
        [Parameter(Mandatory)]
        [string]$Identity
    )
    
    try {
        $acl = Get-Acl -Path "AD:$Identity" -ErrorAction Stop
        return $acl.Access | Where-Object { 
            $_.AccessControlType -eq 'Allow' -and 
            $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN' 
        } | ForEach-Object {
            [PSCustomObject]@{
                Principal = $_.IdentityReference.Value
                Rights    = $_.ActiveDirectoryRights
                Type      = $_.AccessControlType
            }
        }
    }
    catch {
        Write-Log "Error getting delegated permissions for $Identity : $($_.Exception.Message)" -Level Warning
        return $null
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
        $policyInfo = Get-ADPolicyInfo
        $networkTopology = Get-ADNetworkTopology
        $securityConfig = Get-ADSecurityConfiguration

        # Add the detailed information to the forest object
        $forestInfo | Add-Member -MemberType NoteProperty -Name Trusts -Value $trustInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name DomainInfo -Value $domainInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name Sites -Value $siteInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name Policies -Value $policyInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name NetworkTopology -Value $networkTopology
        $forestInfo | Add-Member -MemberType NoteProperty -Name SecurityConfiguration -Value $securityConfig

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

                # Get OU information
                $ouInfo = Get-ADOUInfo -DomainName $domainName

                # Add this line after getting domain controllers
                $replicationInfo = Get-ADReplicationInfo -DomainName $domainName


                [PSCustomObject]@{
                    DomainName           = $domainName
                    DomainMode           = $domain.DomainMode
                    PDCEmulator          = $domain.PDCEmulator
                    RIDMaster            = $domain.RIDMaster
                    InfrastructureMaster = $domain.InfrastructureMaster
                    DomainControllers    = $domainControllers
                    OrganizationalUnits  = $ouInfo
                    ReplicationTopology  = $replicationInfo
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
                    OrganizationalUnits  = $null
                    ReplicationTopology  = $null
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


#region Get-ADReplicationInfo.ps1

function Get-ADReplicationInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    
    try {
        Write-Log "Retrieving replication topology for domain: $DomainName..." -Level Info
        
        # Get replication connections
        $replicationConnections = Get-ADReplicationConnection -Filter * -Server $DomainName | 
        ForEach-Object {
            [PSCustomObject]@{
                FromServer    = $_.ReplicateFromDirectoryServer
                ToServer      = $_.ReplicateToDirectoryServer
                Schedule      = $_.ReplicationSchedule
                Options       = $_.Options
                AutoGenerated = $_.AutoGenerated
            }
        }
        
        # Get replication site links
        $siteLinks = Get-ADReplicationSiteLink -Filter * -Server $DomainName |
        ForEach-Object {
            [PSCustomObject]@{
                Name                 = $_.Name
                Cost                 = $_.Cost
                ReplicationFrequency = $_.ReplicationFrequencyInMinutes
                Sites                = $_.Sites
            }
        }
        
        # Get replication status
        $replicationStatus = Get-ADReplicationPartnerMetadata -Target $DomainName -Scope Domain |
        ForEach-Object {
            [PSCustomObject]@{
                Partner                = $_.Partner
                LastReplicationAttempt = $_.LastReplicationAttempt
                LastReplicationResult  = $_.LastReplicationResult
                LastReplicationSuccess = $_.LastReplicationSuccess
            }
        }
        
        return [PSCustomObject]@{
            Connections = $replicationConnections
            SiteLinks   = $siteLinks
            Status      = $replicationStatus
        }
    }
    catch {
        Write-Log "Error retrieving replication topology for $DomainName : $($_.Exception.Message)" -Level Error
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

