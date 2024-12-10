function Get-ADSecurityConfiguration {
    try {
        Write-Log "Retrieving AD security configuration..." -Level Info

        $securityConfig = [PSCustomObject]@{
            ObjectACLs       = Get-CriticalObjectACLs
            FileShareACLs    = Get-CriticalShareACLs
            SPNConfiguration = Get-SPNConfiguration
        }
        
        return $securityConfig
    }
    catch {
        Write-Log "Error retrieving security configuration: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve security configuration. Check permissions."
    }
}

function Get-CriticalObjectACLs {
    try {
        Write-Log "Collecting ACLs for critical AD objects..." -Level Info
        
        # Get all OUs
        $ous = Get-ADOrganizationalUnit -Filter *
        
        $acls = foreach ($ou in $ous) {
            try {
                $acl = Get-Acl -Path "AD:$ou"
                
                [PSCustomObject]@{
                    OU          = $ou.Name
                    Path        = $ou.path
                    Owner       = $acl.Owner
                    AccessRules = $acl.Access | ForEach-Object {
                        [PSCustomObject]@{
                            Principal  = $_.IdentityReference.Value
                            AccessType = $_.AccessControlType.ToString()
                            Rights     = $_.ActiveDirectoryRights.ToString()
                            Inherited  = $_.IsInherited
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting ACL for $path : $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $acls
    }
    catch {
        Write-Log "Error collecting critical object ACLs: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-CriticalShareACLs {
    try {
        Write-Log "Collecting ACLs for SYSVOL and NETLOGON shares..." -Level Info
        
        $dc = Get-ADDomainController
        $shares = @("SYSVOL", "NETLOGON")
        
        $shareAcls = foreach ($share in $shares) {
            try {
                $path = "\\$($dc.HostName)\$share"
                $acl = Get-Acl -Path $path
                
                [PSCustomObject]@{
                    ShareName   = $share
                    Path        = $path
                    Owner       = $acl.Owner
                    AccessRules = $acl.AccessRules | ForEach-Object {
                        [PSCustomObject]@{
                            Principal  = $_.IdentityReference.Value
                            AccessType = $_.AccessControlType.ToString()
                            Rights     = $_.FileSystemRights.ToString()
                            Inherited  = $_.IsInherited
                        }
                    }
                }
            }
            catch {
                Write-Log "Error getting ACL for $share : $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $shareAcls
    }
    catch {
        Write-Log "Error collecting share ACLs: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-SPNConfiguration {
    try {
        Write-Log "Collecting SPN configuration..." -Level Info
        
        # Get all user accounts with SPNs
        $spnUsers = Get-ADUser -Filter * -Properties ServicePrincipalNames |
        Where-Object { $_.ServicePrincipalNames.Count -gt 0 }
        
        $spnConfig = foreach ($user in $spnUsers) {
            [PSCustomObject]@{
                UserName    = $user.SamAccountName
                Enabled     = $user.Enabled
                SPNs        = $user.ServicePrincipalNames
                IsDuplicate = $false  # Will be checked later
            }
        }
        
        # Check for duplicate SPNs
        $allSpns = $spnUsers | ForEach-Object { $_.ServicePrincipalNames } | Where-Object { $_ }
        $duplicateSpns = $allSpns | Group-Object | Where-Object { $_.Count -gt 1 }
        
        foreach ($dupSpn in $duplicateSpns) {
            $spnConfig | Where-Object { $_.SPNs -contains $dupSpn.Name } | 
            ForEach-Object { $_.IsDuplicate = $true }
        }
        
        return $spnConfig
    }
    catch {
        Write-Log "Error collecting SPN configuration: $($_.Exception.Message)" -Level Error
        return $null
    }
}