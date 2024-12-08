function Get-ADUsers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Users",
        [switch]$Export,
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
            'MemberOf'  # Added MemberOf property
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                # Get group names from MemberOf collection
                $groupMemberships = @($user.MemberOf | ForEach-Object {
                        try {
                            $groupDN = $_
                            $group = Get-ADGroup $groupDN -Properties Name
                            $group.Name
                        }
                        catch {
                            Write-Log "Error resolving group $groupDN : $($_.Exception.Message)" -Level Warning
                            $groupDN  # Return DN if name resolution fails
                        }
                    })

                [PSCustomObject]@{
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $user.DisplayName
                    EmailAddress         = $user.EmailAddress
                    Enabled              = $user.Enabled
                    LastLogonDate        = $user.LastLogonDate
                    PasswordLastSet      = $user.PasswordLastSet
                    PasswordNeverExpires = $user.PasswordNeverExpires
                    PasswordExpired      = $user.PasswordExpired
                    GroupMemberships     = $groupMemberships  # Added group memberships
                    GroupCount           = $groupMemberships.Count  # Added count of groups
                    DistinguishedName    = $user.DistinguishedName
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
                    GroupMemberships     = @()  # Empty array for failed processing
                    GroupCount           = 0    # Zero for failed processing
                    DistinguishedName    = $null
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $users -ExportPath $ExportPath -Export:$Export
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "User retrieval complete" -Completed
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}