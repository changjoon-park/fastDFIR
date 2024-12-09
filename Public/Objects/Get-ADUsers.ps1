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
            'MemberOf',
            'SID'
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                # Check for delegated permissions
                $delegatedPermissions = Get-ObjectDelegatedPermissions -Identity $user.DistinguishedName

                [PSCustomObject]@{
                    SamAccountName       = $user.SamAccountName
                    DisplayName          = $user.DisplayName
                    EmailAddress         = $user.EmailAddress
                    Enabled              = $user.Enabled
                    LastLogonDate        = $user.LastLogonDate
                    PasswordLastSet      = $user.PasswordLastSet
                    PasswordNeverExpires = $user.PasswordNeverExpires
                    PasswordExpired      = $user.PasswordExpired
                    DistinguishedName    = $user.DistinguishedName
                    SID                  = $user.SID
                    DelegatedPermissions = $delegatedPermissions
                    AccountStatus        = if ($user.Enabled) { 
                        if ($user.PasswordExpired) { "Expired" } else { "Active" }
                    }
                    else { "Disabled" }
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
                    DistinguishedName    = $user.DistinguishedName
                    SID                  = $null
                    DelegatedPermissions = @()
                    AccountStatus        = $null
                    AccessStatus         = "Access Error: $($_.Exception.Message)"
                }
            }
        }

        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $users -ExportPath $ExportPath
        
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve users. Check permissions."
    }
}

# Helper function to get delegated permissions
function Get-ObjectDelegatedPermissions {
    param(
        [Parameter(Mandatory)]
        [string]$Identity
    )
    
    try {
        # Ensure the Identity is a valid Distinguished Name
        if (-not [ADSI]::Exists("LDAP://$Identity")) {
            throw "Invalid Distinguished Name or object not found"
        }

        $path = [ADSI]"LDAP://$Identity"
        $acl = $path.psbase.ObjectSecurity

        return $acl.Access | Where-Object { 
            $_.AccessControlType -eq 'Allow' -and 
            $_.IdentityReference -notmatch 'NT AUTHORITY|BUILTIN' 
        } | ForEach-Object {
            [PSCustomObject]@{
                Principal = $_.IdentityReference.Value
                Rights    = $_.ActiveDirectoryRights
                Type      = $_.AccessControlType
            }
        }
    }
    catch {
        Write-Log "Error getting delegated permissions for $Identity : $($_.Exception.Message)" -Level Warning
        return $null
    }
}