function Get-GPPermissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [Guid]$Guid
    )
    
    process {
        try {
            Write-Log "Retrieving permissions for GPO with GUID: $Guid" -Level Info

            # Import the GroupPolicy module
            Import-Module GroupPolicy -ErrorAction Stop

            $permissions = Get-GPPermission -Guid $Guid -All             

            if (-not $permissions) {
                Write-Log "No permissions found for GPO with GUID: $Guid" -Level Warning
                return @()
            }

            # Process and format the permissions into custom objects
            $processedPermissions = $permissions | ForEach-Object {
                [PSCustomObject]@{
                    Trustee     = $_.Trustee
                    TrusteeType = $_.TrusteeType
                    Permission  = $_.Permission
                    Inherited   = $_.Inherited
                }
            }

            Add-Member -InputObject $processedPermissions -MemberType ScriptMethod -Name "ToString" -Value {
                "Trustee: $($this.Trustee), Permission: $($this.Permission)"
            } -Force

            Write-Log "Successfully retrieved permissions for GPO with GUID: $Guid" -Level Info
            return $processedPermissions
        }
        catch {
            Write-Log "Error retrieving GPO permissions for GUID ${Guid}: $($_.Exception.Message)" -Level Error
            return @()
        }
    }
}

#endregion
function Get-GPOLinks {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [Microsoft.GroupPolicy.GPO]$GPO,

        [Parameter(Mandatory)]
        [xml]$XmlReport
    )

    try {
        # Links are usually found under <GPO><LinksTo> in the XML report
        $linksNode = $XmlReport.GPO.LinksTo
        if ($linksNode -and $linksNode.Link) {
            return $linksNode.Link | ForEach-Object {
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
        else {
            Write-Log "No links found for GPO: $($GPO.DisplayName)" -Level Warning
            return @()
        }
    }
    catch {
        Write-Log "Error getting GPO links for $($GPO.DisplayName): $($_.Exception.Message)" -Level Warning
        return @()
    }
}

function Get-ADPolicyInfo {
    [CmdletBinding()]
    param(
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        Write-Log "Retrieving AD Group Policy Object (GPO) information..." -Level Info

        # Define the filter and properties for GPOs
        $filter = '*'  # Retrieve all GPOs; modify if needed
        $properties = @(
            'DisplayName',
            'Id',
            'DomainName',
            'CreationTime',
            'ModificationTime',
            'GpoStatus',
            'WmiFilter'  # Assuming WmiFilter is a property; adjust if necessary
        )

        # Define the processing script for each GPO
        $processingScript = {
            param($gpo)

            # Generate the XML report for the GPO
            $reportXml = Get-GPOReport -Guid $gpo.Id -ReportType XML -ErrorAction Stop
            [xml]$xmlReport = $reportXml

            # Extract GPO links using the Get-GPOLinks function
            $gpoLinks = Get-GPOLinks -GPO $gpo -XmlReport $xmlReport

            # Extract Password Policy Settings
            $passwordPolicies = $xmlReport.SelectNodes("//SecurityOptions/SecurityOption[contains(Name, 'Password')]") | ForEach-Object {
                [PSCustomObject]@{
                    Setting = $_.Name
                    State   = $_.State
                    Value   = $_.SettingNumber
                }
            }

            # Extract Audit Policy Settings
            $auditPolicies = $xmlReport.SelectNodes("//AuditSetting") | ForEach-Object {
                [PSCustomObject]@{
                    Category     = $_.SubcategoryName
                    AuditSuccess = [bool]($_.SettingValue -band 1)
                    AuditFailure = [bool]($_.SettingValue -band 2)
                }
            }

            # Extract WMI Filters
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
            else {
                $null
            }

            # Extract GPO Permissions using Get-GPPermissions
            $gpoPermissions = Get-GPPermissions -Guid $gpo.Id

            # Extract Scripts Configuration
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

            # Extract Registry Settings
            $registrySettings = $xmlReport.SelectNodes("//RegistrySettings/Registry") | ForEach-Object {
                [PSCustomObject]@{
                    KeyPath   = $_.KeyPath
                    ValueName = $_.ValueName
                    Value     = $_.Value
                    Type      = $_.Type
                    Action    = $_.Action
                }
            }

            # Extract File System Changes
            $fileOperations = $xmlReport.SelectNodes("//FileSecurity") | ForEach-Object {
                [PSCustomObject]@{
                    Path               = $_.Path
                    PropagationMode    = $_.PropagationMode
                    SecurityDescriptor = $_.SecurityDescriptor
                    AceType            = $_.AccessControlEntry.Type
                    Rights             = $_.AccessControlEntry.Rights
                }
            }

            # Extract Service Configurations
            $serviceSettings = $xmlReport.SelectNodes("//NTServices/NTService") | ForEach-Object {
                [PSCustomObject]@{
                    ServiceName        = $_.Name
                    StartupType        = $_.StartupType
                    ServiceAction      = $_.ServiceAction
                    SecurityDescriptor = $_.SecurityDescriptor
                }
            }

            # Extract Administrative Template Settings
            $adminTemplates = $xmlReport.SelectNodes("//AdminTemplatePolicies/Policy") | ForEach-Object {
                [PSCustomObject]@{
                    Name       = $_.Name
                    State      = $_.State
                    Category   = $_.Category
                    Class      = $_.Class
                    Parameters = $_.Parameters
                }
            }

            # Extract Software Installation Settings
            $softwareInstallation = $xmlReport.SelectNodes("//SoftwareInstallation/Package") | ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.Name
                    ProductCode    = $_.ProductCode
                    DeploymentType = $_.DeploymentType
                    Action         = $_.Action
                    SourcePath     = $_.SourcePath
                }
            }

            # Extract Network Settings (Drive Mappings)
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

            # Construct the GPO object with all retrieved information
            [PSCustomObject]@{
                Name                 = $gpo.DisplayName
                ID                   = $gpo.Id
                DomainName           = $gpo.DomainName
                CreationTime         = $gpo.CreationTime
                ModificationTime     = $gpo.ModificationTime
                Status               = $gpo.GpoStatus
                Links                = $gpoLinks
                PasswordPolicies     = $passwordPolicies
                AuditPolicies        = $auditPolicies
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

        # Invoke the helper function to retrieve and process GPOs
        $gpoInfo = Invoke-ADRetrievalWithProgress -ObjectType "Policies" `
            -Filter $filter `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving GPOs"

        # Extract Account Lockout Policies
        $lockoutPolicies = Get-ADDefaultDomainPasswordPolicy -Credential $Credential | ForEach-Object {
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

        # Extract Fine-Grained Password Policies
        $fgppPolicies = Get-ADFineGrainedPasswordPolicy -Filter * -Credential $Credential | ForEach-Object {
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

        # Compile the Policy Information Object
        $policyInfo = [PSCustomObject]@{
            GroupPolicies               = $gpoInfo
            DefaultLockoutPolicy        = $lockoutPolicies
            FineGrainedPasswordPolicies = $fgppPolicies
        }

        # Add a ToString method for better output
        Add-Member -InputObject $policyInfo -MemberType ScriptMethod -Name "ToString" -Value {
            "GPOs: $($this.GroupPolicies.Count), Default Policies: $($this.DefaultLockoutPolicy.Count), FGPP: $($this.FineGrainedPasswordPolicies.Count)"
        } -Force 

        return $policyInfo
    }
    catch {
        Write-Log "Error retrieving policy information: $($_.Exception.Message)" -Level Error
    }
    finally {
        Show-ProgressHelper -Activity "AD Inventory" -Status "Completed policy retrieval" -Completed
    }
}