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