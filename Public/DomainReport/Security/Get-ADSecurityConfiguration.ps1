function Get-ADSecurityConfiguration {
    [CmdletBinding()]
    param(
        [System.Management.Automation.PSCredential]$Credential
    )

    try {
        Write-Log "Retrieving AD security configuration..." -Level Info

        # Retrieve Organizational Units (OUs)
        $OUs = Get-ADOrganizationalUnit -Filter * -Properties Name, DistinguishedName -Credential $Credential -ErrorAction Stop

        # Retrieve Domain Controllers (DCs)
        $DCs = Get-ADDomainController -Filter * -Properties HostName -Credential $Credential -ErrorAction Stop
    
        # TODO: Retrieve Users (for SPN Configuration)
        # $Users = Get-ADUser -Filter * -Properties SamAccountName, Enabled, ServicePrincipalNames -Credential $Credential -ErrorAction Stop

        # Compile the security configuration into a PSCustomObject
        $securityConfig = [PSCustomObject]@{
            ObjectACLs       = Get-CriticalObjectACLs -OUs $OUs
            FileShareACLs    = Get-CriticalShareACLs -DCs $DCs
            SPNConfiguration = Get-CriticalShareACLs -DCs $DCs
        }

        # Add ToString method to securityConfig
        Add-Member -InputObject $securityConfig -MemberType ScriptMethod -Name "ToString" -Value {
            "ObjectACLs=$($this.ObjectACLs.Count); FileShareACLs=$($this.FileShareACLs.Count)"
        } -Force

        Write-Log "Successfully retrieved AD security configuration." -Level Info

        return $securityConfig
    }
    catch {
        Write-Log "Error retrieving AD security configuration: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-CriticalObjectACLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$OUs
    )

    try {
        Write-Log "Collecting ACLs for critical AD objects..." -Level Info

        # Define a processing scriptblock for each OU
        $processingScript = {
            param($ou)

            try {
                # Retrieve ACL for the OU
                $acl = Get-Acl -Path ("AD:" + $ou.DistinguishedName)

                # Process Access Rules
                $accessRules = $acl.Access | ForEach-Object {
                    [PSCustomObject]@{
                        Principal  = $_.IdentityReference.Value
                        AccessType = $_.AccessControlType.ToString()
                        Rights     = $_.ActiveDirectoryRights.ToString()
                        Inherited  = $_.IsInherited
                    }
                }

                # Construct the ACL object
                [PSCustomObject]@{
                    OU          = $ou.Name
                    Path        = $ou.DistinguishedName
                    Owner       = $acl.Owner
                    AccessRules = $accessRules
                }
            }
            catch {
                Write-Log "Error getting ACL for $($ou.DistinguishedName): $($_.Exception.Message)" -Level Warning
                return $null
            }
        }

        # Use the helper to process each OU with progress reporting
        $objectACLs = Invoke-ADRetrievalWithProgress -ObjectType "OUs" `
            -Filter "*" `
            -Properties @('Name', 'DistinguishedName') `
            -Credential $null `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving OU ACLs" `
            -InputData $OUs

        # Remove any null entries resulting from errors
        $objectACLs = $objectACLs | Where-Object { $_ -ne $null }

        # Add ToString method to each ACL object
        foreach ($aclObj in $objectACLs) {
            Add-Member -InputObject $aclObj -MemberType ScriptMethod -Name "ToString" -Value {
                "OU=$($this.OU); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
            } -Force
        }

        Write-Log "Successfully collected ACLs for critical AD objects." -Level Info

        return $objectACLs
    }
    catch {
        Write-Log "Error collecting critical object ACLs: $($_.Exception.Message)" -Level Error
        return @()
    }
}

function Get-CriticalShareACLs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$DCs
    )

    try {
        Write-Log "Collecting ACLs for SYSVOL and NETLOGON shares..." -Level Info

        # Define a processing scriptblock for each share
        $processingScript = {
            param($shareInfo)

            try {
                # Construct the share path
                $path = "\\$($shareInfo.HostName)\$($shareInfo.ShareName)"

                # Retrieve ACL for the share
                $acl = Get-Acl -Path $path

                # Process Access Rules
                $accessRules = $acl.Access | ForEach-Object {
                    [PSCustomObject]@{
                        Principal  = $_.IdentityReference.Value
                        AccessType = $_.AccessControlType.ToString()
                        Rights     = $_.FileSystemRights.ToString()
                        Inherited  = $_.IsInherited
                    }
                }

                # Construct the Share ACL object
                [PSCustomObject]@{
                    ShareName   = $shareInfo.ShareName
                    Path        = $path
                    Owner       = $acl.Owner
                    AccessRules = $accessRules
                }
            }
            catch {
                Write-Log "Error getting ACL for $($shareInfo.ShareName): $($_.Exception.Message)" -Level Warning
                return $null
            }
        }

        # Define the shares to retrieve
        $shares = @("SYSVOL", "NETLOGON")

        # Prepare share information from all DCs
        $shareInfos = foreach ($dc in $DCs) {
            foreach ($share in $shares) {
                [PSCustomObject]@{
                    HostName  = $dc.HostName
                    ShareName = $share
                }
            }
        }

        # Use the helper to process each share with progress reporting
        $shareACLs = Invoke-ADRetrievalWithProgress -ObjectType "Shares" `
            -Filter "*" `
            -Properties @('HostName', 'ShareName') `
            -Credential $null `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Share ACLs" `
            -InputData $shareInfos

        # Remove any null entries resulting from errors
        $shareACLs = $shareACLs | Where-Object { $_ -ne $null }

        # Add ToString method to each Share ACL object
        foreach ($shareAclObj in $shareACLs) {
            Add-Member -InputObject $shareAclObj -MemberType ScriptMethod -Name "ToString" -Value {
                "Share=$($this.ShareName); Owner=$($this.Owner); Rules=$($this.AccessRules.Count)"
            } -Force
        }

        Write-Log "Successfully collected ACLs for SYSVOL and NETLOGON shares." -Level Info

        return $shareACLs
    }
    catch {
        Write-Log "Error collecting share ACLs: $($_.Exception.Message)" -Level Error
        return @()
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

# Helper Function: Get-SPNConfiguration
function Get-SPNConfiguration {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [array]$Users
    )

    try {
        Write-Log "Collecting SPN configuration from AD users..." -Level Info

        # Define a processing scriptblock for each user
        $processingScript = {
            param($user)

            try {
                if ($user.ServicePrincipalNames -and $user.ServicePrincipalNames.Count -gt 0) {
                    [PSCustomObject]@{
                        UserName    = $user.SamAccountName
                        Enabled     = $user.Enabled
                        SPNs        = $user.ServicePrincipalNames
                        IsDuplicate = $false
                    }
                }
                else {
                    return $null
                }
            }
            catch {
                Write-Log "Error processing SPNs for user $($user.SamAccountName): $($_.Exception.Message)" -Level Warning
                return $null
            }
        }

        # Use the helper to process each user with progress reporting
        $spnUsers = Invoke-ADRetrievalWithProgress -ObjectType "Users" `
            -Filter "*" `
            -Properties @('SamAccountName', 'Enabled', 'ServicePrincipalNames') `
            -Credential $null `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving SPN Configurations" `
            -InputData $Users

        # Remove any null entries resulting from errors or users without SPNs
        $spnUsers = $spnUsers | Where-Object { $_ -ne $null }

        if ($spnUsers.Count -eq 0) {
            Write-Log "No users with SPNs found." -Level Info
            return @()
        }

        # Check for duplicate SPNs
        # Create a hashtable to track SPN counts
        $spnTable = @{}
        foreach ($spnObj in $spnUsers) {
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
        foreach ($spnObj in $spnUsers) {
            foreach ($spn in $spnObj.SPNs) {
                if ($spnTable[$spn] -gt 1) {
                    $spnObj.IsDuplicate = $true
                    break  # No need to check further SPNs for this user
                }
            }
        }

        # Add ToString method to each SPN configuration object
        foreach ($spnObj in $spnUsers) {
            Add-Member -InputObject $spnObj -MemberType ScriptMethod -Name "ToString" -Value {
                "User=$($this.UserName); Enabled=$($this.Enabled); SPNCount=$($this.SPNs.Count); Duplicate=$($this.IsDuplicate)"
            } -Force
        }

        Write-Log "Successfully collected SPN configurations." -Level Info

        return $spnUsers
    }
    catch {
        Write-Log "Error collecting SPN configuration: $($_.Exception.Message)" -Level Error
        return @()
    }
}