function Get-ADSecurityConfiguration {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "SecurityConfig",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving AD security configuration..." -Level Info

        $securityConfig = [PSCustomObject]@{
            ObjectACLs       = Get-CriticalObjectACLs
            FileShareACLs    = Get-CriticalShareACLs
            SPNConfiguration = Get-SPNConfiguration
            KerberosSettings = Get-KerberosConfiguration
        }

        # Export data
        Export-ADData -ObjectType $ObjectType -Data $securityConfig -ExportPath $ExportPath
        
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
        
        # Get domain root
        $domain = Get-ADDomain
        
        # Critical paths to check
        $criticalPaths = @(
            $domain.DistinguishedName, # Domain root
            "CN=Users,$($domain.DistinguishedName)", # Users container
            "CN=Computers,$($domain.DistinguishedName)", # Computers container
            "CN=System,$($domain.DistinguishedName)"      # System container
        )
        
        # Get all OUs
        $ous = Get-ADOrganizationalUnit -Filter *
        $criticalPaths += $ous.DistinguishedName
        
        $acls = foreach ($path in $criticalPaths) {
            try {
                $acl = Get-Acl -Path "AD:$path"
                
                [PSCustomObject]@{
                    Path        = $path
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
                    AccessRules = $acl.Access | ForEach-Object {
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

function Get-KerberosConfiguration {
    try {
        Write-Log "Collecting Kerberos configuration..." -Level Info
        
        # Get domain controller
        $dc = Get-ADDomainController
        
        # Get Kerberos policy
        $kerbPolicy = Get-GPObject -Name "Default Domain Policy" | 
        Get-GPOReport -ReportType Xml | 
        Select-Xml -XPath "//SecurityOptions/SecurityOption[contains(Name, 'Kerberos')]"
        
        # Get additional Kerberos settings from registry
        $regSettings = Invoke-Command -ComputerName $dc.HostName -ScriptBlock {
            Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters"
        }
        
        return [PSCustomObject]@{
            MaxTicketAge              = $regSettings.MaxTicketAge
            MaxRenewAge               = $regSettings.MaxRenewAge
            MaxServiceAge             = $regSettings.MaxServiceAge
            MaxClockSkew              = $regSettings.MaxClockSkew
            PreAuthenticationRequired = $kerbPolicy.Node.SettingBoolean
            PolicySettings            = $kerbPolicy | ForEach-Object {
                [PSCustomObject]@{
                    Setting = $_.Node.Name
                    State   = $_.Node.State
                    Value   = $_.Node.SettingNumber
                }
            }
        }
    }
    catch {
        Write-Log "Error collecting Kerberos configuration: $($_.Exception.Message)" -Level Error
        return $null
    }
}