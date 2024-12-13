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