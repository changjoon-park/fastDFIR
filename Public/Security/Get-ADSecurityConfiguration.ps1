function Get-ADSecurityConfiguration {
    try {
        Write-Log "Retrieving AD security configuration..." -Level Info

        $securityConfig = [PSCustomObject]@{
            ObjectACLs       = Get-CriticalObjectACLs
            FileShareACLs    = Get-CriticalShareACLs
            SPNConfiguration = Get-SPNConfiguration
        }
        
        # Add ToString method to securityConfig
        Add-Member -InputObject $securityConfig -MemberType ScriptMethod -Name "ToString" -Value {
            "ObjectACLs=$($this.ObjectACLs.Count); FileShareACLs=$($this.FileShareACLs.Count); SPNs=$($this.SPNConfiguration.Count)"
        } -Force
        
        return $securityConfig
    }
    catch {
        Write-Log "Error retrieving security configuration: $($_.Exception.Message)" -Level Error
    }
}

function Get-CriticalObjectACLs {
    try {
        Write-Log "Collecting ACLs for critical AD objects..." -Level Info
        
        if (-not $script:AllOUs -or $script:AllOUs.Count -eq 0) {
            Write-Log "No OU data available in cache." -Level Warning
            return $null
        }

        $acls = @()
        foreach ($ou in $script:AllOUs) {
            try {
                # Getting ACL from AD is still required
                $acl = Get-Acl -Path ("AD:" + $ou.DistinguishedName)
                
                # Convert ACL.Access to a collection of custom objects
                $accessRules = @()
                foreach ($rule in $acl.Access) {
                    $accessRules += [PSCustomObject]@{
                        Principal  = $rule.IdentityReference.Value
                        AccessType = $rule.AccessControlType.ToString()
                        Rights     = $rule.ActiveDirectoryRights.ToString()
                        Inherited  = $rule.IsInherited
                    }
                }

                $aclObject = [PSCustomObject]@{
                    OU          = $ou.Name
                    Path        = $ou.DistinguishedName
                    Owner       = $acl.Owner
                    AccessRules = $accessRules
                }

                # Add ToString method to each ACL object
                Add-Member -InputObject $aclObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "OU=$($this.OU); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
                } -Force

                $acls += $aclObject
            }
            catch {
                Write-Log "Error getting ACL for $($ou.DistinguishedName) : $($_.Exception.Message)" -Level Warning
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
        
        # Use cached DC data
        if (-not $script:AllDCs -or $script:AllDCs.Count -eq 0) {
            Write-Log "No domain controller data available in cache. Cannot retrieve share ACLs." -Level Error
            return $null
        }

        # Pick the first DC from the cached list (or add logic to choose a specific one)
        $dc = $script:AllDCs[0]
        if (-not $dc.HostName) {
            Write-Log "No DC HostName available to form share paths." -Level Error
            return $null
        }

        $shares = @("SYSVOL", "NETLOGON")
        $shareAcls = @()

        foreach ($share in $shares) {
            try {
                $path = "\\$($dc.HostName)\$share"
                $acl = Get-Acl -Path $path

                $accessRules = @()
                foreach ($rule in $acl.AccessRules) {
                    $accessRules += [PSCustomObject]@{
                        Principal  = $rule.IdentityReference.Value
                        AccessType = $rule.AccessControlType.ToString()
                        Rights     = $rule.FileSystemRights.ToString()
                        Inherited  = $rule.IsInherited
                    }
                }

                $shareAclObject = [PSCustomObject]@{
                    ShareName   = $share
                    Path        = $path
                    Owner       = $acl.Owner
                    AccessRules = $accessRules
                }

                # Add ToString method to each share ACL object
                Add-Member -InputObject $shareAclObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Share=$($this.ShareName); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
                } -Force

                $shareAcls += $shareAclObject
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
        Write-Log "Collecting SPN configuration from cached users..." -Level Info
        
        if (-not $script:AllUsers -or $script:AllUsers.Count -eq 0) {
            Write-Log "No user data available in cache." -Level Warning
            return $null
        }

        # Filter users that have SPNs
        $spnUsers = @()
        foreach ($usr in $script:AllUsers) {
            if ($usr.ServicePrincipalNames -and $usr.ServicePrincipalNames.Count -gt 0) {
                $spnUsers += $usr
            }
        }

        if ($spnUsers.Count -eq 0) {
            Write-Log "No users with SPNs found." -Level Info
            return @()
        }

        $spnConfig = @()
        foreach ($user in $spnUsers) {
            $spnObject = [PSCustomObject]@{
                UserName    = $user.SamAccountName
                Enabled     = $user.Enabled
                SPNs        = $user.ServicePrincipalNames
                IsDuplicate = $false
            }

            # Add ToString method
            Add-Member -InputObject $spnObject -MemberType ScriptMethod -Name "ToString" -Value {
                "User=$($this.UserName); Enabled=$($this.Enabled); SPNCount=$($this.SPNs.Count); Duplicate=$($this.IsDuplicate)"
            } -Force

            $spnConfig += $spnObject
        }

        # Check for duplicate SPNs
        # We'll use a hashtable to track counts of SPNs
        $spnTable = @{}
        foreach ($spnObj in $spnConfig) {
            foreach ($spn in $spnObj.SPNs) {
                if ($spnTable.ContainsKey($spn)) {
                    $spnTable[$spn]++
                }
                else {
                    $spnTable[$spn] = 1
                }
            }
        }

        # Mark duplicates
        foreach ($spnObj in $spnConfig) {
            foreach ($spn in $spnObj.SPNs) {
                if ($spnTable[$spn] -gt 1) {
                    $spnObj.IsDuplicate = $true
                    break
                }
            }
        }
        
        return $spnConfig
    }
    catch {
        Write-Log "Error collecting SPN configuration: $($_.Exception.Message)" -Level Error
        return $null
    }
}