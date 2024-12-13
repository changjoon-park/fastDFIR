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