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
            'MemberOf'  # Getting group memberships
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                $groupMemberships = @($user.MemberOf | ForEach-Object {
                        try {
                            $groupDN = $_
                            $group = Get-ADGroup $groupDN -Properties Name -ErrorAction SilentlyContinue
                            if ($group) {
                                $group.Name
                            }
                            else {
                                Write-Log "Group not found: $groupDN" -Level Warning
                                "Unknown Group ($($groupDN.Split(',')[0]))"
                            }
                        }
                        catch {
                            Write-Log "Error resolving group $groupDN : $($_.Exception.Message)" -Level Warning
                            "Unresolved Group ($($groupDN.Split(',')[0]))"
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
                    GroupMemberships     = $groupMemberships
                    GroupCount           = $groupMemberships.Count
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
                    GroupMemberships     = @()
                    GroupCount           = 0
                    DistinguishedName    = $null
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $users -ExportPath $ExportPath
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "User retrieval complete" -Completed
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}