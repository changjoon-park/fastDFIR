# Merged Script - Created 2024-12-12 22:12:32


#region MergedScript.ps1

# Merged Script - Created 2024-12-12 22:12:32


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


#region Find-SuspiciousGroupMemberships.ps1

function Find-SuspiciousGroupMemberships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Groups,
        [object[]]$Users,
        [hashtable]$ApprovedMembers = @{
            "Domain Admins"     = @("Administrator")
            "Enterprise Admins" = @("Administrator")
            "Schema Admins"     = @("Administrator")
        },
        [int]$NewAccountThresholdDays = 30
    )

    $suspiciousFindings = @()
    
    # Get all privileged groups and their known patterns
    $privilegedGroups = @{
        "Domain Admins"     = @{
            MaxMembers     = 5
            RequiredNaming = "admin"
            RiskLevel      = "Critical"
        }
        "Enterprise Admins" = @{
            MaxMembers     = 3
            RequiredNaming = "admin"
            RiskLevel      = "Critical"
        }
        "Schema Admins"     = @{
            MaxMembers     = 2
            RequiredNaming = "admin"
            RiskLevel      = "Critical"
        }
        "Backup Operators"  = @{
            MaxMembers = 5
            RiskLevel  = "High"
        }
    }

    foreach ($group in $Groups) {
        if ($privilegedGroups.ContainsKey($group.Name)) {
            $groupConfig = $privilegedGroups[$group.Name]
            $approvedList = $ApprovedMembers[$group.Name]
            
            # Check total member count
            if ($group.Members.Count -gt $groupConfig.MaxMembers) {
                $suspiciousFindings += [PSCustomObject]@{
                    GroupName    = $group.Name
                    Finding      = "Excessive Members"
                    Details      = "Group has $($group.Members.Count) members, expected max $($groupConfig.MaxMembers)"
                    RiskLevel    = $groupConfig.RiskLevel
                    TimeDetected = Get-Date
                }
            }

            foreach ($memberDN in $group.Members) {
                $member = $Users | Where-Object { $_.DistinguishedName -eq $memberDN }
                if ($member) {
                    # Check if member is approved
                    if (-not ($approvedList -contains $member.SamAccountName)) {
                        $finding = [PSCustomObject]@{
                            GroupName    = $group.Name
                            MemberName   = $member.SamAccountName
                            Finding      = "Unauthorized Member"
                            Details      = "Member not in approved list"
                            RiskLevel    = $groupConfig.RiskLevel
                            TimeDetected = Get-Date
                        }
                        
                        # Additional checks for suspicious patterns
                        if ($member.Created -gt (Get-Date).AddDays(-$NewAccountThresholdDays)) {
                            $finding.Finding = "Recently Created Account in Privileged Group"
                            $finding.RiskLevel = "Critical"
                        }
                        
                        if ($member.Enabled -eq $false) {
                            $finding.Finding = "Disabled Account in Privileged Group"
                        }
                        
                        $suspiciousFindings += $finding
                    }
                }
            }
        }
    }

    return $suspiciousFindings
}

#endregion


#region Find-SuspiciousSPNs.ps1

function Find-SuspiciousSPNs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Computers,
        [object[]]$Users,
        [hashtable]$KnownGoodSPNs = @{
            'WSMAN'               = 'Windows Remote Management'
            'DNS'                 = 'Domain Name Service'
            'HOST'                = 'Host Service'
            'GC'                  = 'Global Catalog'
            'TERMSRV'             = 'Terminal Services'
            'RestrictedKrbHost'   = 'Kerberos Restricted Delegation'
            'exchangeAB'          = 'Exchange Address Book'
            'ldap'                = 'LDAP Service'
            'MSServerClusterMgmt' = 'Failover Cluster Management'
            'SMTP'                = 'Simple Mail Transfer Protocol'
            'MSSQLSvc'            = 'SQL Server'
            'HTTP'                = 'Web Services'
        },
        [string[]]$SuspiciousPatterns = @(
            '\s+',
            '[;|&]',
            '/\.\.', 
            '/cmd\.exe',
            '/powershell\.exe',
            '\.(ps1|bat|cmd|vbs|js)$'
        )
    )

    $results = @()
    
    # Process both computers and users
    $allObjects = @()
    $allObjects += $Computers | Select-Object @{N = 'Name'; E = { $_.Name } }, 
    @{N = 'Type'; E = { 'Computer' } }, 
    'ServicePrincipalNames'
    $allObjects += $Users | Select-Object @{N = 'Name'; E = { $_.SamAccountName } }, 
    @{N = 'Type'; E = { 'User' } }, 
    'ServicePrincipalNames'

    foreach ($obj in $allObjects) {
        if ($obj.ServicePrincipalNames) {
            $suspiciousSPNs = @{}
            $foundSuspicious = $false
            
            foreach ($spn in $obj.ServicePrincipalNames) {
                $prefix = $spn.Split('/')[0]
                $isSuspicious = $false
                $reason = ""

                # Check if it's an unknown SPN prefix
                if (-not $KnownGoodSPNs.ContainsKey($prefix)) {
                    $reason = "Unknown SPN prefix: $prefix"
                    $isSuspicious = $true
                }

                # Check for suspicious patterns even in known good SPNs
                foreach ($pattern in $SuspiciousPatterns) {
                    if ($spn -match $pattern) {
                        $reason = "Suspicious pattern found: $pattern"
                        $isSuspicious = $true
                        break
                    }
                }

                if ($isSuspicious) {
                    $suspiciousSPNs[$spn] = $reason
                    $foundSuspicious = $true
                }
            }

            if ($foundSuspicious) {
                $results += [PSCustomObject]@{
                    ObjectName     = $obj.Name
                    ObjectType     = $obj.Type
                    SuspiciousSPNs = $suspiciousSPNs
                    TimeDetected   = Get-Date
                    RiskLevel      = if ($obj.Type -eq 'User') { 'High' } else { 'Medium' }
                }
            }
        }
    }

    return $results | Sort-Object ObjectName, ObjectType
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
        
        # Add ToString method to securityConfig
        Add-Member -InputObject $securityConfig -MemberType ScriptMethod -Name "ToString" -Value {
            "ObjectACLs=$($this.ObjectACLs.Count); FileShareACLs=$($this.FileShareACLs.Count); SPNs=$($this.SPNConfiguration.Count)"
        } -Force
        
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
                
                $aclObject = [PSCustomObject]@{
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

                # Add ToString method to each ACL object
                Add-Member -InputObject $aclObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "OU=$($this.OU); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
                } -Force

                $aclObject
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
                
                $shareAclObject = [PSCustomObject]@{
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

                # Add ToString method to each share ACL object
                Add-Member -InputObject $shareAclObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Share=$($this.ShareName); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
                } -Force

                $shareAclObject
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
            $spnObject = [PSCustomObject]@{
                UserName    = $user.SamAccountName
                Enabled     = $user.Enabled
                SPNs        = $user.ServicePrincipalNames
                IsDuplicate = $false  # Will be checked later
            }

            # Add ToString method to each SPN config object
            Add-Member -InputObject $spnObject -MemberType ScriptMethod -Name "ToString" -Value {
                "User=$($this.UserName); Enabled=$($this.Enabled); SPNCount=$($this.SPNs.Count); Duplicate=$($this.IsDuplicate)"
            } -Force

            $spnObject
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
                $dc = [PSCustomObject]@{
                    HostName               = $_.HostName
                    IPv4Address            = $_.IPv4Address
                    Site                   = $_.Site
                    IsGlobalCatalog        = $_.IsGlobalCatalog
                    OperatingSystem        = $_.OperatingSystem
                    OperatingSystemVersion = $_.OperatingSystemVersion
                    Enabled                = $_.Enabled
                }

                Add-Member -InputObject $dc -MemberType ScriptMethod -Name "ToString" -Value {
                    "HostName=$($this.HostName); IPv4=$($this.IPv4Address); Site=$($this.Site)"
                } -String
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

        # Add ToString method to domainInfo
        Add-Member -InputObject $domainInfo -MemberType ScriptMethod -Name "ToString" -Value {
            "DomainName=$($this.DomainName); DomainMode=$($this.DomainMode); PDCEmulator=$($this.PDCEmulator); InfrastructureMaster=$($this.InfrastructureMaster); DCs=$($this.DomainControllers.Count); OUs=$($this.OrganizationalUnits.Count)"
        } -Force

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
            $ouObject = [PSCustomObject]@{
                Name              = $ou.Name
                DistinguishedName = $ou.DistinguishedName
                Description       = $ou.Description
                Created           = $ou.Created
                Modified          = $ou.Modified
                ChildOUs          = ($ou.DistinguishedName -split ',OU=' | Select-Object -Skip 1) -join ',OU='
            }

            # Add ToString method to each OU object
            Add-Member -InputObject $ouObject -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); Children=$($this.ChildOUs.Split(',').Count)"
            } -Force

            $ouObject
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
            $info = [PSCustomObject]@{
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
            
            Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); ForestMode=$($this.ForestMode); SchemaMaster=$($this.SchemaMaster); GlobalCatalogs=$($this.GlobalCatalogs.Count); Domains=$($this.Domains.Count)"
            } -Force
            
            $info
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

        # Add ToString method to siteTopology
        Add-Member -InputObject $siteTopology -MemberType ScriptMethod -Name "ToString" -Value {
            "Sites=$($this.Sites.Count); TotalSites=$($this.TotalSites); TotalSubnets=$($this.TotalSubnets); TotalSiteLinks=$($this.TotalSiteLinks); TotalReplConnections=$($this.TotalReplConnections)"
        } -Force

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
        
        $trustInfo = Get-ADTrust -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $info = [PSCustomObject]@{
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
            
            Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); Source=$($this.Source); Target=$($this.Target); TrustType=$($this.TrustType); Direction=$($this.Direction)"
            } -Force
            
            $info
        }

        return $trustInfo
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
            'IPv4Address',
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
            'ServicePrincipalNames',
            'MemberOf'  # Added MemberOf property
        )

        $computers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }

        $computerObjects = Get-ADObjects -ObjectType $ObjectType -Objects $computers -ProcessingScript {
            param($computer)
            
            try {
                $computerObject = [PSCustomObject]@{
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
                    MemberOf               = $computer.MemberOf  # Added MemberOf property
                    AccessStatus           = "Success"
                    NetworkStatus          = "Unknown"
                    IsAlive                = $false
                }

                # Updated ToString method to include group membership count
                Add-Member -InputObject $computerObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); NetworkStatus=$($this.NetworkStatus); IsAlive=$($this.IsAlive); Groups=$($this.MemberOf.Count)"
                } -Force

                $computerObject
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                $computerObject = [PSCustomObject]@{
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
                    MemberOf               = @()  # Empty array for error cases
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                    NetworkStatus          = "Error"
                    IsAlive                = $false
                }

                Add-Member -InputObject $computerObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); NetworkStatus=Error; IsAlive=$($this.IsAlive); Groups=0"
                } -Force 

                $computerObject
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
                $groupObject = [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory
                    GroupScope             = $group.GroupScope
                    TotalNestedMemberCount = $group.Members.Count
                    Members                = $group.Members
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Success"
                }

                Add-Member -InputObject $groupObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); Category=$($this.GroupCategory); Scope=$($this.GroupScope); Members=$($this.TotalNestedMemberCount)"
                } -Force

                $groupObject
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                
                $groupObject = [PSCustomObject]@{
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

                Add-Member -InputObject $groupObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); Status=Error"
                } -Force

                $groupObject
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
                $userObject = [PSCustomObject]@{
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

                Add-Member -InputObject $userObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "SamAccountName=$($this.SamAccountName); Status=$($this.AccountStatus); Groups=$($this.MemberOf.Count)"
                } -Force

                $userObject
            }
            catch {
                Write-Log "Error processing user $($user.SamAccountName): $($_.Exception.Message)" -Level Warning
                $userObject = [PSCustomObject]@{
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $null
                    EmailAddress         = $null
                    Enabled              = $null
                    LastLogonDate        = $null
                    PasswordLastSet      = $null
                    PasswordNeverExpires = $null
                    PasswordExpired      = $null
                    DistinguishedName    = $user.DistinguishedName
                    MemberOf             = @()
                    AccountStatus        = "Error"
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }

                Add-Member -InputObject $userObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "SamAccountName=$($this.SamAccountName); Status=Error; Groups=0"
                } -Force

                $userObject
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
        # Initialize tracking variables
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @{}
        $errors = @{}
        $componentTiming = @{}

        # Define collection components
        $components = @{
            'ForestInfo'     = { Get-ADForestInfo }
            'TrustInfo'      = { Get-ADTrustInfo }
            'Sites'          = { Get-ADSiteInfo }
            'DomainInfo'     = { Get-ADDomainInfo }
            'Users'          = { Get-ADUsers }
            'Computers'      = { Get-ADComputers }
            'Groups'         = { Get-ADGroupsAndMembers }
            'SecurityConfig' = { Get-ADSecurityConfiguration }
        }

        # Sequential collection
        foreach ($component in $components.Keys) {
            $componentSw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                Write-Log "Collecting $component..." -Level Info
                $results[$component] = & $components[$component]
                $componentTiming[$component] = Convert-MillisecondsToReadable -Milliseconds $componentSw.ElapsedMilliseconds
            }
            catch {
                $errors[$component] = $_.Exception.Message
                $componentTiming[$component] = Convert-MillisecondsToReadable -Milliseconds $componentSw.ElapsedMilliseconds
                Write-Log "Error collecting ${component}: $($_.Exception.Message)" -Level Error
                if (-not $ContinueOnError) { throw }
            }
        }

        # Create the final report object
        $domainReport = [PSCustomObject]@{
            CollectionTime     = Get-Date
            CollectionStatus   = if ($errors.Count -eq 0) { "Complete" } else { "Partial" }
            Errors             = $errors
            PerformanceMetrics = $componentTiming
            TotalExecutionTime = Convert-MillisecondsToReadable -Milliseconds $sw.ElapsedMilliseconds
            BasicInfo          = [PSCustomObject]@{
                ForestInfo = $results['ForestInfo']
                TrustInfo  = $results['TrustInfo']
                Sites      = $results['Sites']
                DomainInfo = $results['DomainInfo']
            }
            DomainObjects      = [PSCustomObject]@{
                Users     = $results['Users']
                Computers = $results['Computers']
                Groups    = $results['Groups']
            }
            SecuritySettings   = [PSCustomObject]@{
                SecurityConfig = $results['SecurityConfig']
            }
        }

        # Add report generation metadata
        Add-Member -InputObject $domainReport -MemberType NoteProperty -Name "ReportGeneration" -Value @{
            GeneratedBy       = $env:USERNAME
            GeneratedOn       = Get-Date
            ComputerName      = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }

        # Add methods to the report object
        Add-DomainReportMethods -DomainReport $domainReport


        # Export the report if requested
        if ($ExportPath) {
            $exportFile = Join-Path $ExportPath ("DomainReport_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            $domainReport | ConvertTo-Json -Depth 10 | Out-File $exportFile
            Write-Log "Report exported to: $exportFile" -Level Info
        }

        return $domainReport
    }
    catch {
        Write-Log "Critical error in Get-DomainReport: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        $sw.Stop()
        Write-Log "Total execution time: $($sw.ElapsedMilliseconds)ms" -Level Info
    }
}

# Main method addition function
function Add-DomainReportMethods {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$DomainReport
    )
    
    # Add ToString methods
    Add-ToStringMethods -DomainReport $DomainReport
    
    # Add Search methods
    Add-SearchMethods -DomainReport $DomainReport
    
    # Add Network methods
    Add-NetworkMethods -DomainReport $DomainReport
    
    # Add Security methods
    Add-SecurityMethods -DomainReport $DomainReport
}

# Individual method groups
function Add-ToStringMethods {
    param ($DomainReport)
    
    $basicInfoToString = {
        $forest = if ($this.ForestInfo.Name) { $this.ForestInfo.Name } else { "N/A" }
        $domain = if ($this.DomainInfo.DomainName) { $this.DomainInfo.DomainName } else { "N/A" }
        $sites = if ($this.Sites.TotalSites) { $this.Sites.TotalSites } else { "0" }
        $trusts = if ($this.TrustInfo) { $this.TrustInfo.Count } else { "0" }
        
        return "forest=$forest, domain=$domain, sites=$sites, trusts=$trusts"
    }

    $domainObjectsToString = {
        $users = if ($this.Users) { $this.Users.Count } else { "0" }
        $computers = if ($this.Computers) { $this.Computers.Count } else { "0" }
        $groups = if ($this.Groups) { $this.Groups.Count } else { "0" }
        
        return "users=$users, computers=$computers, groups=$groups"
    }

    $securitySettingsToString = {
        $spns = if ($this.SecurityConfig.SPNConfiguration) { $this.SecurityConfig.SPNConfiguration.Count } else { "0" }
        $acls = if ($this.SecurityConfig.ObjectACLs) { $this.SecurityConfig.ObjectACLs.Count } else { "0" }
        return "SPNs=$spns, ACLs=$acls"
    }

    Add-Member -InputObject $DomainReport.BasicInfo -MemberType ScriptMethod -Name "ToString" -Value $basicInfoToString -Force
    Add-Member -InputObject $DomainReport.DomainObjects -MemberType ScriptMethod -Name "ToString" -Value $domainObjectsToString -Force
    Add-Member -InputObject $DomainReport.SecuritySettings -MemberType ScriptMethod -Name "ToString" -Value $securitySettingsToString -Force
}

function Add-SearchMethods {
    param ($DomainReport)
    
    $searchUsers = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Users) {
            Write-Log "No user data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Users | Where-Object {
            $_.SamAccountName -like "*$SearchTerm*" -or
            $_.DisplayName -like "*$SearchTerm*" -or
            $_.EmailAddress -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No users found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    $searchComputers = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computer data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Computers | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.IPv4Address -like "*$SearchTerm*" -or
            $_.DNSHostName -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No computers found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchUsers" -Value $searchUsers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchComputers" -Value $searchComputers -Force
}

function Add-NetworkMethods {
    param ($DomainReport)
    
    $networkMethods = @{
        TestTargetConnection = Get-TestTargetConnectionMethod
        TestConnections      = Get-TestConnectionsMethod
        ScanCommonPorts      = Get-ScanCommonPortsMethod
        ScanTargetPorts      = Get-ScanTargetPortsMethod
    }

    foreach ($method in $networkMethods.GetEnumerator()) {
        Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name $method.Key -Value $method.Value -Force
    }
}

function Add-SecurityMethods {
    param ($DomainReport)
    
    $securityMethods = @{
        FindSuspiciousSPNs    = Get-FindSuspiciousSPNsMethod
        DisplaySuspiciousSPNs = Get-DisplaySuspiciousSPNsMethod
    }

    foreach ($method in $securityMethods.GetEnumerator()) {
        Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name $method.Key -Value $method.Value -Force
    }
}

# Helper functions for network methods
function Get-TestTargetConnectionMethod {
    return {
        param(
            [Parameter(Mandatory = $true)]
            $ADComputer
        )

        $target = if ($ADComputer.DNSHostName) { $ADComputer.DNSHostName } else { $ADComputer.Name }

        if ([string]::IsNullOrEmpty($target)) {
            Write-Log "Invalid target. The specified ADComputer has no resolvable DNSHostName or Name." -Level Warning
            return $null
        }

        $reachable = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue

        $ADComputer.IsAlive = $reachable
        $ADComputer.NetworkStatus = if ($reachable) { "Online" } else { "Offline/Unreachable" }

        return [PSCustomObject]@{
            Computer      = $target
            IsAlive       = $ADComputer.IsAlive
            NetworkStatus = $ADComputer.NetworkStatus
        }
    }
}

function Get-TestConnectionsMethod {
    return {
        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computers found in the domain report. Cannot test connections." -Level Warning
            return $null
        }

        $results = @()
        foreach ($comp in $this.DomainObjects.Computers) {
            $target = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }

            if ([string]::IsNullOrEmpty($target)) {
                Write-Log "Skipping $($comp.Name) due to no valid DNSHostName or Name." -Level Warning
                $comp.IsAlive = $false
                $comp.NetworkStatus = "Invalid Target"
                $results += [PSCustomObject]@{
                    Computer      = $comp.Name
                    IsAlive       = $comp.IsAlive
                    NetworkStatus = $comp.NetworkStatus
                }
                continue
            }

            $reachable = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            $comp.IsAlive = $reachable
            $comp.NetworkStatus = if ($reachable) { "Online" } else { "Offline/Unreachable" }

            $results += [PSCustomObject]@{
                Computer      = $target
                IsAlive       = $comp.IsAlive
                NetworkStatus = $comp.NetworkStatus
            }
        }

        if (-not $this.PSObject.Properties.Name.Contains('NetworkConnectivityResults')) {
            Add-Member -InputObject $this -MemberType NoteProperty -Name 'NetworkConnectivityResults' -Value $results
        }
        else {
            $this.NetworkConnectivityResults = $results
        }

        return $results
    }
}

function Get-ScanCommonPortsMethod {
    return {
        param(
            [int[]]$Ports = (80, 443, 445, 3389, 5985),
            [int]$Timeout = 1000
        )

        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computers found in the domain report. Cannot scan ports." -Level Warning
            return $null
        }

        $results = @()
        foreach ($comp in $this.DomainObjects.Computers) {
            if (-not $comp.IsAlive) {
                Write-Log "Skipping $($comp.Name) because IsAlive=$($comp.IsAlive)" -Level Info
                continue
            }

            $target = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }

            if ([string]::IsNullOrEmpty($target)) {
                Write-Log "Invalid target for $($comp.Name): No resolvable DNSHostName or Name." -Level Warning
                continue
            }

            foreach ($port in $Ports) {
                $tcp = New-Object System.Net.Sockets.TcpClient
                try {
                    $asyncResult = $tcp.BeginConnect($target, $port, $null, $null)
                    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)
                    
                    if ($wait -and $tcp.Connected) {
                        $tcp.EndConnect($asyncResult)
                        $results += [PSCustomObject]@{
                            Computer = $target
                            Port     = $port
                            Status   = "Open"
                        }
                    }
                    else {
                        $results += [PSCustomObject]@{
                            Computer = $target
                            Port     = $port
                            Status   = "Closed/Filtered"
                        }
                    }
                }
                catch {
                    $results += [PSCustomObject]@{
                        Computer = $target
                        Port     = $port
                        Status   = "Error: $($_.Exception.Message)"
                    }
                }
                finally {
                    $tcp.Close()
                }
            }
        }

        if (-not $this.PSObject.Properties.Name.Contains('NetworkPortScanResults')) {
            Add-Member -InputObject $this -MemberType NoteProperty -Name 'NetworkPortScanResults' -Value $results
        }
        else {
            $this.NetworkPortScanResults = $results
        }

        return $this.NetworkPortScanResults
    }
}

function Get-ScanTargetPortsMethod {
    return {
        param(
            [Parameter(Mandatory = $true)]
            $ADComputer,
            [Parameter(Mandatory = $true)]
            [int[]]$Ports
        )

        if (-not $ADComputer.IsAlive) {
            Write-Log "Skipping $($ADComputer.Name) because IsAlive=$($ADComputer.IsAlive)" -Level Warning
            return $null
        }

        $target = if ($ADComputer.DNSHostName) { $ADComputer.DNSHostName } else { $ADComputer.Name }

        if ([string]::IsNullOrEmpty($target)) {
            Write-Log "Invalid target. The specified ADComputer has no resolvable DNSHostName or Name." -Level Warning
            return $null
        }

        $results = @()
        foreach ($port in $Ports) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                $asyncResult = $tcp.BeginConnect($target, $port, $null, $null)
                $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)

                if ($wait -and $tcp.Connected) {
                    $tcp.EndConnect($asyncResult)
                    $results += [PSCustomObject]@{
                        Computer = $target
                        Port     = $port
                        Status   = "Open"
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        Computer = $target
                        Port     = $port
                        Status   = "Closed/Filtered"
                    }
                }
            }
            catch {
                $results += [PSCustomObject]@{
                    Computer = $target
                    Port     = $port
                    Status   = "Error: $($_.Exception.Message)"
                }
            }
            finally {
                $tcp.Close()
            }
        }

        return $results
    }
}

function Get-FindSuspiciousSPNsMethod {
    return {
        $spnResults = Find-SuspiciousSPNs -Computers $this.DomainObjects.Computers -Users $this.DomainObjects.Users
        
        if (-not $this.SecuritySettings.PSObject.Properties.Name.Contains('SuspiciousSPNs')) {
            Add-Member -InputObject $this.SecuritySettings -MemberType NoteProperty -Name 'SuspiciousSPNs' -Value $spnResults
        }
        else {
            $this.SecuritySettings.SuspiciousSPNs = $spnResults
        }
        
        return $spnResults
    }
}

function Get-DisplaySuspiciousSPNsMethod {
    return {
        if (-not $this.SecuritySettings.PSObject.Properties.Name.Contains('SuspiciousSPNs')) {
            Write-Log "No suspicious SPNs found. Running FindSuspiciousSPNs..." -Level Info
            $this.FindSuspiciousSPNs()
        }
    
        if ($this.SecuritySettings.SuspiciousSPNs) {
            Write-Log "`nSuspicious SPNs Found:" -Level Warning
            $this.SecuritySettings.SuspiciousSPNs | ForEach-Object {
                Write-Log "`nObject: $($_.ObjectName) ($($_.ObjectType))" -Level Warning
                Write-Log "Risk Level: $($_.RiskLevel)" -Level $(if ($_.RiskLevel -eq 'High') { 'Error' } else { 'Warning' })
                $_.SuspiciousSPNs.GetEnumerator() | ForEach-Object {
                    Write-Log "  SPN: $($_.Key)" -Level Warning
                    Write-Log "  Reason: $($_.Value)" -Level Warning
                }
            }
        }
        else {
            Write-Log "`nNo suspicious SPNs found." -Level Info
        }
    }
}

#endregion


#region Test-AdminRights.ps1

function Test-AdminRights {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $adminStatus = @{
        IsADAdmin = $false
        IsOUAdmin = $false
        Username  = $Username
    }

    # Check ADAdmin status (Domain/Enterprise Admin membership)
    try {
        $user = Get-ADUser $Username -Properties MemberOf
        $adminGroups = $user.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name
        if ($adminGroups -match "Domain Admins|Enterprise Admins|Schema Admins|BUILTIN\\Administrators") {
            $adminStatus.IsADAdmin = $true
        }
    }
    catch {
        Write-Warning "Error checking AD Admin status for $Username : $_"
    }

    # Check OUAdmin status (looking for OU-level permissions)
    try {
        $ouPermissions = Get-ADOrganizationalUnit -Filter * | ForEach-Object {
            Get-ACL "AD:$($_.DistinguishedName)" | ForEach-Object {
                $_.Access | Where-Object { 
                    $_.IdentityReference -like "*$Username*" -and 
                    $_.ActiveDirectoryRights -match "CreateChild|DeleteChild|WriteProperty"
                }
            }
        }
        if ($ouPermissions) {
            $adminStatus.IsOUAdmin = $true
        }
    }
    catch {
        Write-Warning "Error checking OU Admin status for $Username : $_"
    }

    # Return results
    return $adminStatus
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


#region Convert-MillisecondsToReadable.ps1

function Convert-MillisecondsToReadable {
    param ([int64]$Milliseconds)
    $timespan = [TimeSpan]::FromMilliseconds($Milliseconds)
    return "$($timespan.Minutes) min $($timespan.Seconds) seconds"
}

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

