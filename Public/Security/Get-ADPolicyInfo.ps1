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