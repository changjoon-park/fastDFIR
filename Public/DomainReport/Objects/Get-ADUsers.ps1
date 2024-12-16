function Get-ADUsers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Users",
        [switch]$IncludeDisabled,
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving user accounts from AD..." -Level Info

        # Define the filter based on whether to include disabled users
        $filter = if ($IncludeDisabled) { '*' } else { 'Enabled -eq $true' }

        # Define the properties to retrieve
        $properties = @(
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

        # Define the processing script for each user
        $processingScript = {
            param($user)

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

            # Add a ToString method for better readability
            Add-Member -InputObject $userObject -MemberType ScriptMethod -Name "ToString" -Value {
                "SamAccountName=$($this.SamAccountName); Status=$($this.AccountStatus); Groups=$($this.MemberOf.Count)"
            } -Force

            $userObject
        }

        # Invoke the helper function
        return Invoke-ADRetrievalWithProgress -ObjectType $ObjectType `
            -Filter $filter `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Users"
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
    }
}