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
            'AdminCount', # Added for privileged account detection
            'UserAccountControl'  # Added for account status
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        # Get privileged groups for reference
        $privilegedGroups = @(
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Administrators',
            'Account Operators',
            'Backup Operators',
            'Server Operators'
        )
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            
            try {
                # Check if user is privileged
                $isPrivileged = $false
                $privilegedGroupMemberships = @()
                foreach ($group in $user.MemberOf) {
                    $groupName = (Get-ADGroup $group).Name
                    if ($privilegedGroups -contains $groupName) {
                        $isPrivileged = $true
                        $privilegedGroupMemberships += $groupName
                    }
                }

                # Check for delegated permissions
                $delegatedPermissions = Get-ObjectDelegatedPermissions -Identity $user.DistinguishedName

                # Determine account type
                $accountType = switch -Regex ($user.DistinguishedName) {
                    'OU=Service Accounts,' { 'ServiceAccount' }
                    'CN=Managed Service Accounts,' { 'ManagedServiceAccount' }
                    default { 'UserAccount' }
                }

                [PSCustomObject]@{
                    SamAccountName             = $user.SamAccountName
                    DisplayName                = $user.DisplayName
                    EmailAddress               = $user.EmailAddress
                    Enabled                    = $user.Enabled
                    LastLogonDate              = $user.LastLogonDate
                    PasswordLastSet            = $user.PasswordLastSet
                    PasswordNeverExpires       = $user.PasswordNeverExpires
                    PasswordExpired            = $user.PasswordExpired
                    DistinguishedName          = $user.DistinguishedName
                    AccountType                = $accountType
                    IsPrivileged               = $isPrivileged
                    PrivilegedGroupMemberships = $privilegedGroupMemberships
                    DelegatedPermissions       = $delegatedPermissions
                    AdminCount                 = $user.AdminCount
                    AccountStatus              = if ($user.Enabled) { 
                        if ($user.PasswordExpired) { "Expired" } else { "Active" }
                    }
                    else { "Disabled" }
                    AccessStatus               = "Success"
                }
            }
            catch {
                Write-Log "Error processing user $($user.SamAccountName): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    SamAccountName             = $user.SamAccountName
                    DisplayName                = $null
                    EmailAddress               = $null
                    Enabled                    = $null
                    LastLogonDate              = $null
                    PasswordLastSet            = $null
                    PasswordNeverExpires       = $null
                    PasswordExpired            = $null
                    DistinguishedName          = $user.DistinguishedName
                    AccountType                = $null
                    IsPrivileged               = $null
                    PrivilegedGroupMemberships = @()
                    DelegatedPermissions       = @()
                    AdminCount                 = $null
                    AccountStatus              = $null
                    AccessStatus               = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
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
        $acl = Get-Acl -Path "AD:$Identity" -ErrorAction Stop
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