function Test-AdminRights {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username,
        
        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

    $adminStatus = @{
        IsADAdmin = $false
        IsOUAdmin = $false
        Username  = $Username
    }

    # Prepare base parameters for queries
    $userParams = @{ Identity = $Username; ErrorAction = 'Stop' }
    if ($Credential) {
        $userParams.Credential = $Credential
    }

    # Check AD Admin status (Domain/Enterprise Admin membership)
    try {
        $user = Get-ADUser @userParams -Properties MemberOf
        if ($user -and $user.MemberOf) {
            $groupParams = @{ ErrorAction = 'Stop' }
            if ($Credential) {
                $groupParams.Credential = $Credential
            }
            $adminGroups = $user.MemberOf | Get-ADGroup @groupParams | Select-Object -ExpandProperty Name
            if ($adminGroups -match "Domain Admins|Enterprise Admins|Schema Admins|BUILTIN\\Administrators") {
                $adminStatus.IsADAdmin = $true
            }
        }
    }
    catch {
        Write-Warning "Error checking AD Admin status for $Username : $_"
    }

    # Check OU Admin status (looking for OU-level permissions)
    try {
        $ouParams = @{ Filter = '*'; ErrorAction = 'Stop' }
        if ($Credential) {
            $ouParams.Credential = $Credential
        }

        $ouList = Get-ADOrganizationalUnit @ouParams -Properties DistinguishedName
        foreach ($ou in $ouList) {
            # Get ACL without credential (Get-ACL AD: doesn't support credentials directly)
            # If needed, consider running the ACL check as current user, or 
            # impersonate user with runas. For now, this just checks under current context.
            $acl = Get-ACL "AD:$($ou.DistinguishedName)"
            $aclMatches = $acl.Access | Where-Object {
                $_.IdentityReference -like "*$Username*" -and
                $_.ActiveDirectoryRights -match "CreateChild|DeleteChild|WriteProperty"
            }
            if ($aclMatches) {
                $adminStatus.IsOUAdmin = $true
                break
            }
        }
    }
    catch {
        Write-Warning "Error checking OU Admin status for $Username : $_"
    }

    # Return results
    return $adminStatus
}