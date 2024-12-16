# Merged Script - Created 2024-12-15 22:57:13


#region MergedScript.ps1

# Merged Script - Created 2024-12-15 22:57:13


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


#region Get-ADPolicyInfo.ps1

function Get-GPOLinks {
    param (
        [Parameter(Mandatory)]
        $GPO,

        [Parameter(Mandatory)]
        [xml]$XmlReport
    )

    try {
        # Links are usually found under <GPO><LinksTo> in the XML report
        $linksNode = $XmlReport.GPO.LinksTo
        if ($linksNode -and $linksNode.Link) {
            $linksNode.Link | ForEach-Object {
                [PSCustomObject]@{
                    Location   = $_.SOMPath
                    Enabled    = $_.Enabled
                    NoOverride = $_.NoOverride
                    Type       = switch -Regex ($_.SOMPath) {
                        '^[^/]+$' { 'Domain' }
                        '^OU=' { 'OU' }
                        '^CN=Sites' { 'Site' }
                        default { 'Unknown' }
                    }
                }
            }
        }
    }
    catch {
        Write-Log "Error getting GPO links for $($GPO.DisplayName): $($_.Exception.Message)" -Level Warning
        return $null
    }
}

function Get-ADPolicyInfo {
    try {
        Write-Log "Retrieving AD Group Policy Object information..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing policy retrieval..."

        # Get all GPOs
        $gpos = Get-GPO -All | ForEach-Object {
            $gpo = $_
            Show-ProgressHelper -Activity "Processing GPOs" -Status "Processing $($gpo.DisplayName)"

            # Retrieve GPO Report Once
            $report = Get-GPOReport -Guid $gpo.Id -ReportType XML
            [xml]$xmlReport = $report

            # Get GPO links using the pre-fetched XML
            $gpoLinks = Get-GPOLinks -GPO $gpo -XmlReport $xmlReport

            # Extract password policy settings inline
            $passwordPolicies = $xmlReport.SelectNodes("//SecurityOptions/SecurityOption[contains(Name, 'Password')]")
            $passwordPolicy = $passwordPolicies | ForEach-Object {
                [PSCustomObject]@{
                    Setting = $_.Name
                    State   = $_.State
                    Value   = $_.SettingNumber
                }
            }

            # Extract audit policy settings inline
            $auditPolicies = $xmlReport.SelectNodes("//AuditSetting")
            $auditPolicy = $auditPolicies | ForEach-Object {
                [PSCustomObject]@{
                    Category     = $_.SubcategoryName
                    AuditSuccess = [bool]($_.SettingValue -band 1)
                    AuditFailure = [bool]($_.SettingValue -band 2)
                }
            }

            # Get WMI Filters
            $wmiFilters = if ($gpo.WmiFilter) {
                [PSCustomObject]@{
                    Name             = $gpo.WmiFilter.Name
                    Description      = $gpo.WmiFilter.Description
                    Query            = $gpo.WmiFilter.Query
                    Author           = $gpo.WmiFilter.Author
                    CreationTime     = $gpo.WmiFilter.CreationTime
                    LastModifiedTime = $gpo.WmiFilter.LastModifiedTime
                }
            }

            # Get GPO Permissions (assuming Get-GPPermissions is defined elsewhere)
            $gpoPermissions = Get-GPPermissions -Guid $gpo.Id -All | ForEach-Object {
                [PSCustomObject]@{
                    Trustee        = $_.Trustee.Name
                    Permission     = $_.Permission
                    Inherited      = $_.Inherited
                    DelegationType = $_.TrusteeType
                }
            }

            # Get Scripts Configuration
            $scriptPolicies = $xmlReport.SelectNodes("//Scripts") | ForEach-Object {
                # Ensure the script path is valid before hashing
                $hashValue = $null
                if (Test-Path $_.Command) {
                    $hashValue = (Get-FileHash -Path $_.Command -ErrorAction SilentlyContinue).Hash
                }

                [PSCustomObject]@{
                    Type             = $_.Type
                    Command          = $_.Command
                    Parameters       = $_.Parameters
                    ExecutionContext = $_.RunAs
                    Hash             = $hashValue
                }
            }

            # Get Registry Settings
            $registrySettings = $xmlReport.SelectNodes("//RegistrySettings/Registry") | ForEach-Object {
                [PSCustomObject]@{
                    KeyPath   = $_.KeyPath
                    ValueName = $_.ValueName
                    Value     = $_.Value
                    Type      = $_.Type
                    Action    = $_.Action
                }
            }

            # Get File System Changes
            $fileOperations = $xmlReport.SelectNodes("//FileSecurity") | ForEach-Object {
                [PSCustomObject]@{
                    Path               = $_.Path
                    PropagationMode    = $_.PropagationMode
                    SecurityDescriptor = $_.SecurityDescriptor
                    AceType            = $_.AccessControlEntry.Type
                    Rights             = $_.AccessControlEntry.Rights
                }
            }

            # Get Service Configurations
            $serviceSettings = $xmlReport.SelectNodes("//NTServices/NTService") | ForEach-Object {
                [PSCustomObject]@{
                    ServiceName        = $_.Name
                    StartupType        = $_.StartupType
                    ServiceAction      = $_.ServiceAction
                    SecurityDescriptor = $_.SecurityDescriptor
                }
            }

            # Get Administrative Template Settings
            $adminTemplates = $xmlReport.SelectNodes("//AdminTemplatePolicies/Policy") | ForEach-Object {
                [PSCustomObject]@{
                    Name       = $_.Name
                    State      = $_.State
                    Category   = $_.Category
                    Class      = $_.Class
                    Parameters = $_.Parameters
                }
            }

            # Get Software Installation Settings
            $softwareInstallation = $xmlReport.SelectNodes("//SoftwareInstallation/Package") | ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.Name
                    ProductCode    = $_.ProductCode
                    DeploymentType = $_.DeploymentType
                    Action         = $_.Action
                    SourcePath     = $_.SourcePath
                }
            }

            # Get Network Settings (Drive Mappings)
            $networkSettings = $xmlReport.SelectNodes("//DriveMapSettings/DriveMap") | ForEach-Object {
                [PSCustomObject]@{
                    DriveLetter = $_.DriveLetter
                    Path        = $_.Path
                    Label       = $_.Label
                    Persistent  = $_.Persistent
                    Action      = $_.Action
                }
            }

            # Determine if Computer/User settings are enabled based on GpoStatus
            $computerEnabled = ($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]"ComputerSettingsDisabled" -and $gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]"AllSettingsDisabled")
            $userEnabled = ($gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]"UserSettingsDisabled" -and $gpo.GpoStatus -ne [Microsoft.GroupPolicy.GpoStatus]"AllSettingsDisabled")

            [PSCustomObject]@{
                Name                 = $gpo.DisplayName
                ID                   = $gpo.Id
                DomainName           = $gpo.DomainName
                CreationTime         = $gpo.CreationTime
                ModificationTime     = $gpo.ModificationTime
                Status               = $gpo.GpoStatus
                Links                = $gpoLinks
                PasswordPolicies     = $passwordPolicy
                AuditPolicies        = $auditPolicy
                ComputerEnabled      = $computerEnabled
                UserEnabled          = $userEnabled
                WMIFilters           = $wmiFilters
                Permissions          = $gpoPermissions
                Scripts              = $scriptPolicies
                RegistrySettings     = $registrySettings
                FileOperations       = $fileOperations
                ServiceSettings      = $serviceSettings
                AdminTemplates       = $adminTemplates
                SoftwareInstallation = $softwareInstallation
                NetworkSettings      = $networkSettings
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

        # Add a ToString method for better output
        Add-Member -InputObject $policyInfo -MemberType ScriptMethod -Name "ToString" -Value {
            "GPOs: $($this.GroupPolicies.Count), Default Policies: $($this.DefaultLockoutPolicy.Count), FGPP: $($this.FineGrainedPasswordPolicies.Count)"
        }

        return $policyInfo
    }
    catch {
        Write-Log "Error retrieving policy information: $($_.Exception.Message)" -Level Error
    }
    finally {
        Show-ProgressHelper -Activity "AD Inventory" -Status "Completed policy retrieval" -Completed
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
    }
}

function Get-CriticalObjectACLs {
    try {
        Write-Log "Collecting ACLs for critical AD objects..." -Level Info
        
        if (-not $script:AllOUs -or $script:AllOUs.Count -eq 0) {
            Write-Log "No OU data available in cache." -Level Warning
            return $null
        }

        $acls = @()
        foreach ($ou in $script:AllOUs) {
            try {
                # Getting ACL from AD is still required
                $acl = Get-Acl -Path ("AD:" + $ou.DistinguishedName)
                
                # Convert ACL.Access to a collection of custom objects
                $accessRules = @()
                foreach ($rule in $acl.Access) {
                    $accessRules += [PSCustomObject]@{
                        Principal  = $rule.IdentityReference.Value
                        AccessType = $rule.AccessControlType.ToString()
                        Rights     = $rule.ActiveDirectoryRights.ToString()
                        Inherited  = $rule.IsInherited
                    }
                }

                $aclObject = [PSCustomObject]@{
                    OU          = $ou.Name
                    Path        = $ou.DistinguishedName
                    Owner       = $acl.Owner
                    AccessRules = $accessRules
                }

                # Add ToString method to each ACL object
                Add-Member -InputObject $aclObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "OU=$($this.OU); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
                } -Force

                $acls += $aclObject
            }
            catch {
                Write-Log "Error getting ACL for $($ou.DistinguishedName) : $($_.Exception.Message)" -Level Warning
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
        
        # Use cached DC data
        if (-not $script:AllDCs -or $script:AllDCs.Count -eq 0) {
            Write-Log "No domain controller data available in cache. Cannot retrieve share ACLs." -Level Error
            return $null
        }

        # Pick the first DC from the cached list (or add logic to choose a specific one)
        $dc = $script:AllDCs[0]
        if (-not $dc.HostName) {
            Write-Log "No DC HostName available to form share paths." -Level Error
            return $null
        }

        $shares = @("SYSVOL", "NETLOGON")
        $shareAcls = @()

        foreach ($share in $shares) {
            try {
                $path = "\\$($dc.HostName)\$share"
                $acl = Get-Acl -Path $path

                $accessRules = @()
                foreach ($rule in $acl.AccessRules) {
                    $accessRules += [PSCustomObject]@{
                        Principal  = $rule.IdentityReference.Value
                        AccessType = $rule.AccessControlType.ToString()
                        Rights     = $rule.FileSystemRights.ToString()
                        Inherited  = $rule.IsInherited
                    }
                }

                $shareAclObject = [PSCustomObject]@{
                    ShareName   = $share
                    Path        = $path
                    Owner       = $acl.Owner
                    AccessRules = $accessRules
                }

                # Add ToString method to each share ACL object
                Add-Member -InputObject $shareAclObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Share=$($this.ShareName); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
                } -Force

                $shareAcls += $shareAclObject
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
        Write-Log "Collecting SPN configuration from cached users..." -Level Info
        
        if (-not $script:AllUsers -or $script:AllUsers.Count -eq 0) {
            Write-Log "No user data available in cache." -Level Warning
            return $null
        }

        # Filter users that have SPNs
        $spnUsers = @()
        foreach ($usr in $script:AllUsers) {
            if ($usr.ServicePrincipalNames -and $usr.ServicePrincipalNames.Count -gt 0) {
                $spnUsers += $usr
            }
        }

        if ($spnUsers.Count -eq 0) {
            Write-Log "No users with SPNs found." -Level Info
            return @()
        }

        $spnConfig = @()
        foreach ($user in $spnUsers) {
            $spnObject = [PSCustomObject]@{
                UserName    = $user.SamAccountName
                Enabled     = $user.Enabled
                SPNs        = $user.ServicePrincipalNames
                IsDuplicate = $false
            }

            # Add ToString method
            Add-Member -InputObject $spnObject -MemberType ScriptMethod -Name "ToString" -Value {
                "User=$($this.UserName); Enabled=$($this.Enabled); SPNCount=$($this.SPNs.Count); Duplicate=$($this.IsDuplicate)"
            } -Force

            $spnConfig += $spnObject
        }

        # Check for duplicate SPNs
        # We'll use a hashtable to track counts of SPNs
        $spnTable = @{}
        foreach ($spnObj in $spnConfig) {
            foreach ($spn in $spnObj.SPNs) {
                if ($spnTable.ContainsKey($spn)) {
                    $spnTable[$spn]++
                }
                else {
                    $spnTable[$spn] = 1
                }
            }
        }

        # Mark duplicates
        foreach ($spnObj in $spnConfig) {
            foreach ($spn in $spnObj.SPNs) {
                if ($spnTable[$spn] -gt 1) {
                    $spnObj.IsDuplicate = $true
                    break
                }
            }
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
        Write-Log "Retrieving AD domain information from cached data..." -Level Info
    
        if (-not $script:Domain) {
            Write-Log "Domain data not available in cache." -Level Warning
            return $null
        }

        # If domain controllers are not available, handle it gracefully
        $domainControllers = $null
        if ($script:AllDCs) {
            $domainControllers = @()
            foreach ($dcItem in $script:AllDCs) {
                $dc = [PSCustomObject]@{
                    HostName               = $dcItem.HostName
                    IPv4Address            = $dcItem.IPv4Address
                    Site                   = $dcItem.Site
                    IsGlobalCatalog        = $dcItem.IsGlobalCatalog
                    OperatingSystem        = $dcItem.OperatingSystem
                    OperatingSystemVersion = $dcItem.OperatingSystemVersion
                    Enabled                = $dcItem.Enabled
                }

                Add-Member -InputObject $dc -MemberType ScriptMethod -Name "ToString" -Value {
                    "HostName=$($this.HostName); IPv4=$($this.IPv4Address); Site=$($this.Site)"
                } -Force

                $domainControllers += $dc
            }
        }
        else {
            Write-Log "No cached domain controller data found." -Level Warning
            $domainControllers = "Access Denied or Connection Failed"
        }

        $ouInfo = Get-ADOUInfo  # Now uses cached $script:AllOUs

        $domainInfo = [PSCustomObject]@{
            DomainName           = $script:Domain.Name
            DomainMode           = $script:Domain.DomainMode
            PDCEmulator          = $script:Domain.PDCEmulator
            RIDMaster            = $script:Domain.RIDMaster
            InfrastructureMaster = $script:Domain.InfrastructureMaster
            DomainControllers    = $domainControllers
            OrganizationalUnits  = $ouInfo
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
        Write-Log "Retrieving OU information from cached data..." -Level Info
        
        if (-not $script:AllOUs) {
            Write-Log "No OU data available in cache." -Level Warning
            return $null
        }

        $ouInfo = @()
        foreach ($ou in $script:AllOUs) {
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

            $ouInfo += $ouObject
        }
        
        return $ouInfo
    }
    catch {
        Write-Log "Error retrieving OU information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADForestInfo.ps1

function Get-ADForestInfo {
    try {
        Write-Log "Retrieving AD forest information from cached data..." -Level Info

        if (-not $script:ForestInfo) {
            Write-Log "No forest information available in cache." -Level Warning
            return $null
        }

        $info = [PSCustomObject]@{
            Name                = $script:ForestInfo.Name
            ForestMode          = $script:ForestInfo.ForestMode
            SchemaMaster        = $script:ForestInfo.SchemaMaster
            DomainNamingMaster  = $script:ForestInfo.DomainNamingMaster
            GlobalCatalogs      = $script:ForestInfo.GlobalCatalogs
            Sites               = $script:ForestInfo.Sites
            Domains             = $script:ForestInfo.Domains
            RootDomain          = $script:ForestInfo.RootDomain
            SchemaNamingContext = $script:ForestInfo.SchemaNamingContext
            DistinguishedName   = $script:ForestInfo.DistinguishedName
        }
            
        Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
            "Name=$($this.Name); ForestMode=$($this.ForestMode); SchemaMaster=$($this.SchemaMaster); GlobalCatalogs=$($this.GlobalCatalogs.Count); Domains=$($this.Domains.Count)"
        } -Force
        
        return $info
    }
    catch {
        Write-Log "Error retrieving forest information: $($_.Exception.Message)" -Level Error
        return $null
    }
}

#endregion


#region Get-ADSiteInfo.ps1

function Get-ADSiteInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving AD site information from cached data..." -Level Info
        
        # Use cached AllSites data instead of re-querying AD
        $sites = foreach ($site in $script:AllSites) {
            # Filter subnets that belong to this site using the cached AllSubnets
            $subnets = $script:AllSubnets | Where-Object {
                # Assuming each subnet object has a 'Site' property that references the site DN
                $_.Site -eq $site.DistinguishedName
            } | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Location    = $_.Location
                    Description = $_.Description
                }
            }

            # Create the site object with all information using cached data
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Created                = $site.Created
                Modified               = $site.Modified
                Subnets                = $subnets

                # SiteLinks and ReplicationConnections were previously retrieved and stored
                # If you need them per site, consider filtering them by a site-related property
                SiteLinks              = $script:AllSiteLinks
                ReplicationConnections = $script:AllReplConnections
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

        # Add a ToString method to siteTopology
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
        Write-Log "Retrieving AD trust information from cached data..." -Level Info
        
        if (-not $script:AllTrusts) {
            Write-Log "No trust data available in cache." -Level Warning
            return $null
        }

        $trustInfo = $script:AllTrusts | ForEach-Object {
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
        [string]$ObjectType = "Computers"
    )
    
    try {
        Write-Log "Retrieving computer accounts from cached data..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing computer retrieval..."

        # Check if cached data is available
        if (-not $script:AllComputers) {
            Write-Log "No cached computer data found." -Level Warning
            return $null
        }

        $computerObjects = Get-ADObjects -ObjectType $ObjectType -Objects $script:AllComputers -ProcessingScript {
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
                    MemberOf               = $computer.MemberOf
                    AccessStatus           = "Success"
                    NetworkStatus          = "Unknown"
                    IsAlive                = $false
                }

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
                    MemberOf               = @()
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
    }
}

#endregion


#region Get-ADGroupsAndMembers.ps1

function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Groups"
    )
    
    try {
        Write-Log "Retrieving groups and members from cached data..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        # Check if cached data is available
        if (-not $script:AllGroups) {
            Write-Log "No cached group data found." -Level Warning
            return $null
        }

        $groupObjects = Get-ADObjects -ObjectType $ObjectType -Objects $script:AllGroups -ProcessingScript {
            param($group)
            
            try {
                $groupObject = [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory
                    GroupScope             = $group.GroupScope
                    TotalNestedMemberCount = if ($group.Members) { $group.Members.Count } else { 0 }
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
    }
}

#endregion


#region Get-ADUsers.ps1

function Get-ADUsers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Users",
        [switch]$IncludeDisabled
    )
    
    try {
        Write-Log "Retrieving user accounts from cached data..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing user retrieval..."
        
        # We previously filtered users by Enabled or Disabled state when querying AD directly.
        # Now we have all users cached. Let's filter in memory if needed.
        $filteredUsers = $script:AllUsers
        if (-not $IncludeDisabled) {
            $filteredUsers = $filteredUsers | Where-Object { $_.Enabled -eq $true }
        }

        if (-not $filteredUsers) {
            Write-Log "No user data available based on the specified criteria." -Level Warning
            return $null
        }

        $userObjects = Get-ADObjects -ObjectType $ObjectType -Objects $filteredUsers -ProcessingScript {
            param($user)

            try {
                $accountStatus = if ($user.Enabled) {
                    if ($user.PasswordExpired) { "Expired" } else { "Active" }
                }
                else {
                    "Disabled"
                }

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
                    AccountStatus        = $accountStatus
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


#region Get-DFIRReport.ps1

## TODO

#endregion


#region Get-DomainReport.ps1

function Get-DomainReport {
    [CmdletBinding(DefaultParameterSetName = 'Collect')]
    param(
        [Parameter(ParameterSetName = 'Collect')]
        [switch]$Export,
        
        [Parameter(ParameterSetName = 'Import', Mandatory = $true)]
        [string]$ImportPath
    )

    # If importing from file
    if ($PSCmdlet.ParameterSetName -eq 'Import') {
        try {
            Write-Log "Importing domain report from $ImportPath..." -Level Info
            
            if (-not (Test-Path $ImportPath)) {
                throw "Import file not found: $ImportPath"
            }

            # Read and convert JSON content
            $importedContent = Get-Content -Path $ImportPath -Raw | ConvertFrom-Json

            # Create a new PSCustomObject with the imported data
            $domainReport = [PSCustomObject]@{
                CollectionTime     = [DateTime]::Parse($importedContent.CollectionTime)
                CollectionStatus   = $importedContent.CollectionStatus
                CollectionRights   = $importedContent.CollectionRights
                Errors             = $importedContent.Errors
                PerformanceMetrics = $importedContent.PerformanceMetrics
                TotalExecutionTime = $importedContent.TotalExecutionTime
                BasicInfo          = $importedContent.BasicInfo
                DomainObjects      = $importedContent.DomainObjects
                SecuritySettings   = $importedContent.SecuritySettings
                ReportGeneration   = $importedContent.ReportGeneration
            }

            # Add methods back to the imported object
            Add-DomainReportMethods -DomainReport $domainReport

            Write-Log "Successfully imported domain report from $ImportPath" -Level Info
            return $domainReport
        }
        catch {
            Write-Log "Error importing domain report: $($_.Exception.Message)" -Level Error
            throw
        }
    }

    # COLLECTION LOGIC
    try {
        Write-Log "Verifying domain membership..." -Level Info
        # Check if the computer is domain-joined by attempting a simple AD query
        try {
            $null = Get-ADDomain -ErrorAction Stop
        }
        catch {
            Write-Log "This computer does not appear to be joined to a domain or cannot access AD." -Level Error
            return  # or handle differently if needed
        }

        # Check current user admin rights
        Write-Log "Checking administrative rights..." -Level Info
        $currentUser = $env:USERNAME
        $adminRights = Test-AdminRights -Username $currentUser

        # If not AD Admin, prompt for credentials
        $adminCreds = $null
        if (-not $adminRights.IsADAdmin) {
            Write-Log "Current user is not an AD Admin. Prompting for alternate credentials..." -Level Warning
            $adminCreds = Get-Credential -Message "Enter credentials for an AD Admin user"
            
            # Re-check admin rights using the supplied credentials
            $adminRights = Test-AdminRights -Username $adminCreds.UserName -Credential $adminCreds

            # If still not AD admin and not OU admin, no further data collection
            if ((-not $adminRights.IsADAdmin) -and (-not $adminRights.IsOUAdmin)) {
                Write-Log "User does not have AD Admin or OU Admin rights. No data will be collected." -Level Warning
                return
            }
        }

        # Initialize AD Data now that we know our rights and optional credential
        Initialize-ADData -AdminRights $adminRights -Credential $adminCreds

        # Define components based on admin rights and credential
        $components = @{}
        
        # Always get DomainInfo if we have any admin or OU admin rights
        # (If you want DomainInfo only for certain roles, adjust as needed)
        $components['DomainInfo'] = {
            if ($adminCreds) { Get-ADDomainInfo -Credential $adminCreds } else { Get-ADDomainInfo }
        }

        if ($adminRights.IsADAdmin) {
            Write-Log "AD Admin rights confirmed - collecting all data" -Level Info
            # Full access components
            $components += @{
                'ForestInfo'     = {
                    if ($adminCreds) { Get-ADForestInfo -Credential $adminCreds } else { Get-ADForestInfo }
                }
                'TrustInfo'      = {
                    if ($adminCreds) { Get-ADTrustInfo -Credential $adminCreds } else { Get-ADTrustInfo }
                }
                'Sites'          = {
                    if ($adminCreds) { Get-ADSiteInfo -Credential $adminCreds } else { Get-ADSiteInfo }
                }
                'Users'          = {
                    if ($adminCreds) { Get-ADUsers -Credential $adminCreds } else { Get-ADUsers }
                }
                'Computers'      = {
                    if ($adminCreds) { Get-ADComputers -Credential $adminCreds } else { Get-ADComputers }
                }
                'Groups'         = {
                    if ($adminCreds) { Get-ADGroupsAndMembers -Credential $adminCreds } else { Get-ADGroupsAndMembers }
                }
                'PolicyInfo'     = {
                    if ($adminCreds) { Get-ADPolicyInfo -Credential $adminCreds } else { Get-ADPolicyInfo }
                }
                'SecurityConfig' = {
                    if ($adminCreds) { Get-ADSecurityConfiguration -Credential $adminCreds } else { Get-ADSecurityConfiguration }
                }
            }
        }
        elseif ($adminRights.IsOUAdmin) {
            Write-Log "OU Admin rights detected - collecting limited data" -Level Info
            # Limited access components: Users, Computers, Groups only
            $components += @{
                'Users'     = {
                    if ($adminCreds) { Get-ADUsers -Credential $adminCreds } else { Get-ADUsers }
                }
                'Computers' = {
                    if ($adminCreds) { Get-ADComputers -Credential $adminCreds } else { Get-ADComputers }
                }
                'Groups'    = {
                    if ($adminCreds) { Get-ADGroupsAndMembers -Credential $adminCreds } else { Get-ADGroupsAndMembers }
                }
            }
        }

        # Initialize tracking variables
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @{}
        $errors = @{}
        $componentTiming = @{}

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
            CollectionRights   = $adminRights
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
                PolicyInfo     = $results['PolicyInfo']
                SecurityConfig = $results['SecurityConfig']
            }
        }

        # Add report generation metadata
        Add-Member -InputObject $domainReport -MemberType NoteProperty -Name "ReportGeneration" -Value @{
            GeneratedBy       = $currentUser
            GeneratedOn       = Get-Date
            ComputerName      = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            UserRights        = $adminRights
        }

        # Add methods to the report object
        Add-DomainReportMethods -DomainReport $domainReport

        # Export if switch is set
        if ($Export) {
            $domainReport.Export()  # Use the Export method with default path
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

#endregion


#region Get-EventReport.ps1

## TODO

#endregion


#region Add-DomainReportMethods.ps1

function Add-DomainReportMethods {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$DomainReport
    )
    
    # Add ToString methods
    Add-ToStringMethods -DomainReport $DomainReport

    # Add Export methods
    Add-ExportMethod -DomainReport $DomainReport
    
    # Add Search methods
    Add-SearchMethods -DomainReport $DomainReport
    
    # Add Network methods
    Add-NetworkMethods -DomainReport $DomainReport
    
    # Add Security methods
    Add-SecurityMethods -DomainReport $DomainReport
}


#endregion


#region Add-ExportMethod.ps1


function Add-ExportMethod {
    param ($DomainReport)
    
    $exportReport = {
        param(
            [string]$ExportPath
        )
            
        try {
            Write-Log "Starting export operation..." -Level Info
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Initializing export..."

            # Use provided path or default from config
            $finalPath = if ($ExportPath) {
                $ExportPath
            }
            else {
                $script:Config.ExportPath
            }

            # Ensure export directory exists
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Checking export directory..." -PercentComplete 20
            if (-not (Test-Path $finalPath)) {
                New-Item -ItemType Directory -Path $finalPath -Force | Out-Null
                Write-Log "Created export directory: $finalPath" -Level Info
            }
    
            # Prepare export file path
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Preparing export file..." -PercentComplete 40
            $exportFile = Join-Path $finalPath ("DomainReport_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            
            # Convert to JSON
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Converting report to JSON..." -PercentComplete 60
            $jsonContent = $this | ConvertTo-Json -Depth 10

            # Write to file
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Writing to file..." -PercentComplete 80
            $jsonContent | Out-File $exportFile

            Show-ProgressHelper -Activity "Domain Report Export" -Status "Export completed" -PercentComplete 100
            Write-Log "Report successfully exported to: $exportFile" -Level Info

            # Complete the progress bar
            Show-ProgressHelper -Activity "Domain Report Export" -Completed
            return $exportFile
        }
        catch {
            Write-Log "Error exporting report: $($_.Exception.Message)" -Level Error
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Export failed" -Completed
            return $null
        }
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "Export" -Value $exportReport -Force
}

#endregion


#region Add-NetworkMethods.ps1

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

#endregion


#region Add-SearchMethods.ps1

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

    $searchGroups = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Groups) {
            Write-Log "No group data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Groups | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.Description -like "*$SearchTerm*" -or
            $_.GroupCategory -like "*$SearchTerm*" -or
            $_.GroupScope -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No groups found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchUsers" -Value $searchUsers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchComputers" -Value $searchComputers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchGroups" -Value $searchGroups -Force
}

#endregion


#region Add-SecurityMethods.ps1

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


#region Add-ToStringMethods.ps1

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

function Add-ExportMethod {
    param ($DomainReport)
    
    $exportReport = {
        param(
            [string]$ExportPath
        )
            
        try {
            Write-Log "Starting export operation..." -Level Info
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Initializing export..."

            # Use provided path or default from config
            $finalPath = if ($ExportPath) {
                $ExportPath
            }
            else {
                $script:Config.ExportPath
            }

            # Ensure export directory exists
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Checking export directory..." -PercentComplete 20
            if (-not (Test-Path $finalPath)) {
                New-Item -ItemType Directory -Path $finalPath -Force | Out-Null
                Write-Log "Created export directory: $finalPath" -Level Info
            }
    
            # Prepare export file path
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Preparing export file..." -PercentComplete 40
            $exportFile = Join-Path $finalPath ("DomainReport_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            
            # Convert to JSON
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Converting report to JSON..." -PercentComplete 60
            $jsonContent = $this | ConvertTo-Json -Depth 10

            # Write to file
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Writing to file..." -PercentComplete 80
            $jsonContent | Out-File $exportFile

            Show-ProgressHelper -Activity "Domain Report Export" -Status "Export completed" -PercentComplete 100
            Write-Log "Report successfully exported to: $exportFile" -Level Info

            # Complete the progress bar
            Show-ProgressHelper -Activity "Domain Report Export" -Completed
            return $exportFile
        }
        catch {
            Write-Log "Error exporting report: $($_.Exception.Message)" -Level Error
            Show-ProgressHelper -Activity "Domain Report Export" -Status "Export failed" -Completed
            return $null
        }
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "Export" -Value $exportReport -Force
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

    $searchGroups = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Groups) {
            Write-Log "No group data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Groups | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.Description -like "*$SearchTerm*" -or
            $_.GroupCategory -like "*$SearchTerm*" -or
            $_.GroupScope -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No groups found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchUsers" -Value $searchUsers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchComputers" -Value $searchComputers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchGroups" -Value $searchGroups -Force
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


#region Find-SuspiciousGroupMemberships.ps1

function Find-SuspiciousGroupMemberships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Groups,

        [Parameter(Mandatory)]
        [object[]]$Users,

        # ApprovedMembers hash for certain groups; if not present, no member is implicitly approved.
        [hashtable]$ApprovedMembers = @{
            "Domain Admins"     = @("Administrator")
            "Enterprise Admins" = @("Administrator")
            "Schema Admins"     = @("Administrator")
        },

        [int]$NewAccountThresholdDays = 30
    )

    # Pre-build a lookup for users by their DistinguishedName for faster lookups
    $userByDN = @{}
    foreach ($u in $Users) {
        if ($u.DistinguishedName) {
            $userByDN[$u.DistinguishedName] = $u
        }
    }

    $suspiciousFindings = @()
    
    # Define privileged groups and their constraints
    $privilegedGroups = @{
        "Domain Admins"     = @{
            MaxMembers = 5
            RiskLevel  = "Critical"
        }
        "Enterprise Admins" = @{
            MaxMembers = 3
            RiskLevel  = "Critical"
        }
        "Schema Admins"     = @{
            MaxMembers = 2
            RiskLevel  = "Critical"
        }
        "Backup Operators"  = @{
            MaxMembers = 5
            RiskLevel  = "High"
        }
    }

    foreach ($group in $Groups) {
        if ($privilegedGroups.ContainsKey($group.Name)) {
            $groupConfig = $privilegedGroups[$group.Name]

            # Get the approved list for this group if defined, else empty
            $approvedList = $ApprovedMembers[$group.Name]
            if (-not $approvedList) { $approvedList = @() }

            # Check if the group exceeds the maximum expected membership
            if ($group.Members.Count -gt $groupConfig.MaxMembers) {
                $suspiciousFindings += [PSCustomObject]@{
                    GroupName    = $group.Name
                    Finding      = "Excessive Members"
                    Details      = "Group has $($group.Members.Count) members, expected max $($groupConfig.MaxMembers)"
                    RiskLevel    = $groupConfig.RiskLevel
                    TimeDetected = Get-Date
                }
            }

            # Check each member in the group
            foreach ($memberDN in $group.Members) {
                # Attempt to retrieve the member from the lookup
                $member = $userByDN[$memberDN]
                if ($member) {
                    # If the member is not on the approved list, consider it suspicious
                    if (-not ($approvedList -contains $member.SamAccountName)) {
                        $finding = [PSCustomObject]@{
                            GroupName    = $group.Name
                            MemberName   = $member.SamAccountName
                            Finding      = "Unauthorized Member"
                            Details      = "Member not in approved list"
                            RiskLevel    = $groupConfig.RiskLevel
                            TimeDetected = Get-Date
                        }
                        
                        # If the account was recently created, escalate severity
                        if ($member.Created -gt (Get-Date).AddDays(-$NewAccountThresholdDays)) {
                            $finding.Finding = "Recently Created Account in Privileged Group"
                            $finding.RiskLevel = "Critical"
                        }

                        # If the account is disabled, flag this
                        if ($member.Enabled -eq $false) {
                            $finding.Finding = "Disabled Account in Privileged Group"
                        }
                        
                        $suspiciousFindings += $finding
                    }
                }
                else {
                    # Could not find the user in the provided list - this might also be suspicious,
                    # or could indicate the user data is incomplete. Consider logging a warning.
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

function Initialize-ADData {
    # Ensure the AD module is imported
    Import-ADModule

    Write-Log "Initializing AD data cache..."
    
    # Retrieve and store users (with all needed properties in advance)
    $script:AllUsers = Get-ADUser -Filter * -Properties SamAccountName, DistinguishedName, Enabled, Created, MemberOf, ServicePrincipalNames, EmailAddress, DisplayName, PasswordLastSet, PasswordNeverExpires, PasswordExpired, LastLogonDate

    # Retrieve and store computers
    $script:AllComputers = Get-ADComputer -Filter * -Properties IPv4Address, DistinguishedName, OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate, Created, Modified, DNSHostName, ServicePrincipalNames, MemberOf

    # Retrieve and store groups
    $script:AllGroups = Get-ADGroup -Filter * -Properties Description, GroupCategory, GroupScope, Members, MemberOf, DistinguishedName, Created, Modified

    Write-Log "AD data cache initialized. Users: $($script:AllUsers.Count), Computers: $($script:AllComputers.Count), Groups: $($script:AllGroups.Count)"
}

#endregion


#region Convert-MillisecondsToReadable.ps1

function Convert-MillisecondsToReadable {
    param ([int64]$Milliseconds)
    $timespan = [TimeSpan]::FromMilliseconds($Milliseconds)
    return "$($timespan.Minutes) min $($timespan.Seconds) seconds"
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
        return $false
    }
    catch {
        Write-Log "Failed to import ActiveDirectory module: $($_.Exception.Message)" -Level Error
        return $false
    }
    return $true
}

#endregion


#region Initialize-ADData.ps1

function Initialize-ADData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminRights,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    Write-Log "Initializing AD data cache..."

    # Define property sets for each object type
    $userProperties = @(
        'SamAccountName',
        'DistinguishedName',
        'Enabled',
        'Created',
        'MemberOf',
        'ServicePrincipalNames',
        'EmailAddress',
        'DisplayName',
        'PasswordLastSet',
        'PasswordNeverExpires',
        'PasswordExpired',
        'LastLogonDate'
    )

    $computerProperties = @(
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
        'MemberOf'
    )

    $ouProperties = @(
        'DistinguishedName',
        'Name',
        'Description',
        'Created',
        'Modified'
    )

    $siteProperties = @(
        'DistinguishedName',
        'Name',
        'Location',
        'Description',
        'Created',
        'Modified'
    )

    # Build parameter hashtables for each query including optional credentials
    $userParams = @{ Filter = '*'; Properties = $userProperties }
    $computerParams = @{ Filter = '*'; Properties = $computerProperties }
    $groupParams = @{ Filter = '*'; Properties = '*' }
    $gpoParams = @{ All = $true }
    $ouParams = @{ Filter = '*'; Properties = $ouProperties }
    $dcParams = @{ Filter = '*' }
    $forestParams = @{ }
    $siteParams = @{ Filter = '*'; Properties = $siteProperties }
    $subnetParams = @{ Filter = '*'; Properties = '*' }
    $siteLinkParams = @{ Filter = '*'; Properties = '*' }
    $replConnectionParams = @{ Filter = '*'; Properties = '*' }
    $trustParams = @{ Filter = '*'; Properties = '*' }

    if ($Credential) {
        $userParams.Credential = $Credential
        $computerParams.Credential = $Credential
        $groupParams.Credential = $Credential
        $gpoParams.Credential = $Credential
        $ouParams.Credential = $Credential
        $dcParams.Credential = $Credential
        $forestParams.Credential = $Credential
        $siteParams.Credential = $Credential
        $subnetParams.Credential = $Credential
        $siteLinkParams.Credential = $Credential
        $replConnectionParams.Credential = $Credential
        $trustParams.Credential = $Credential
    }

    if ($adminRights.IsADAdmin) {
        Write-Log "AD Admin rights confirmed - collecting all data" -Level Info

        $script:AllUsers = Get-ADUser @userParams
        $script:AllComputers = Get-ADComputer @computerParams
        $script:AllGroups = Get-ADGroup @groupParams
        $script:AllPolicies = Get-GPO @gpoParams
        $script:AllOUs = Get-ADOrganizationalUnit @ouParams
        $script:AllDCs = Get-ADDomainController @dcParams
        $script:ForestInfo = Get-ADForest @forestParams
        $script:AllSites = Get-ADReplicationSite @siteParams
        $script:AllSubnets = Get-ADReplicationSubnet @subnetParams
        $script:AllSiteLinks = Get-ADReplicationSiteLink @siteLinkParams
        $script:AllReplConnections = Get-ADReplicationConnection @replConnectionParams
        $script:AllTrusts = Get-ADTrust @trustParams
    }
    elseif ($AdminRights.IsOUAdmin) {
        Write-Log "OU Admin rights detected - collecting limited data" -Level Info

        $script:AllUsers = Get-ADUser @userParams
        $script:AllComputers = Get-ADComputer @computerParams
        $script:AllGroups = Get-ADGroup @groupParams
    }

    # Summary log
    Write-Log ("AD data cache initialized: " +
        "Users: $($script:AllUsers.Count), " +
        "Computers: $($script:AllComputers.Count), " +
        "Groups: $($script:AllGroups.Count), " +
        "Policies: $($script:AllPolicies.Count), " +
        "OUs: $($script:AllOUs.Count), " +
        "DomainControllers: $($script:AllDCs.Count), " +
        "Sites: $($script:AllSites.Count), " +
        "Trusts: $($script:AllTrusts.Count)")
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


#region Test-AdminRights.ps1

function Test-AdminRights {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $adminStatus = @{
        IsADAdmin = $false
        IsOUAdmin = $false
        Username  = $Username
    }

    # Prepare base parameters for queries
    $userParams = @{ Identity = $Username; ErrorAction = 'Stop' }
    if ($Credential) {
        $userParams.Credential = $Credential
    }

    # Check AD Admin status (Domain/Enterprise Admin membership)
    try {
        $user = Get-ADUser @userParams -Properties MemberOf
        if ($user -and $user.MemberOf) {
            $groupParams = @{ ErrorAction = 'Stop' }
            if ($Credential) {
                $groupParams.Credential = $Credential
            }
            $adminGroups = $user.MemberOf | Get-ADGroup @groupParams | Select-Object -ExpandProperty Name
            if ($adminGroups -match "Domain Admins|Enterprise Admins|Schema Admins|BUILTIN\\Administrators") {
                $adminStatus.IsADAdmin = $true
            }
        }
    }
    catch {
        Write-Warning "Error checking AD Admin status for $Username : $_"
    }

    # Check OU Admin status (looking for OU-level permissions)
    try {
        $ouParams = @{ Filter = '*'; ErrorAction = 'Stop' }
        if ($Credential) {
            $ouParams.Credential = $Credential
        }

        $ouList = Get-ADOrganizationalUnit @ouParams -Properties DistinguishedName
        foreach ($ou in $ouList) {
            # Get ACL without credential (Get-ACL AD: doesn't support credentials directly)
            # If needed, consider running the ACL check as current user, or 
            # impersonate user with runas. For now, this just checks under current context.
            $acl = Get-ACL "AD:$($ou.DistinguishedName)"
            $aclMatches = $acl.Access | Where-Object {
                $_.IdentityReference -like "*$Username*" -and
                $_.ActiveDirectoryRights -match "CreateChild|DeleteChild|WriteProperty"
            }
            if ($aclMatches) {
                $adminStatus.IsOUAdmin = $true
                break
            }
        }
    }
    catch {
        Write-Warning "Error checking OU Admin status for $Username : $_"
    }

    # Return results
    return $adminStatus
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

