function Test-AdminRights {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    $adminStatus = @{
        IsADAdmin = $false
        IsOUAdmin = $false
        Username  = $Username
    }

    # Check ADAdmin status (Domain/Enterprise Admin membership)
    try {
        $user = Get-ADUser $Username -Properties MemberOf
        $adminGroups = $user.MemberOf | Get-ADGroup | Select-Object -ExpandProperty Name
        if ($adminGroups -match "Domain Admins|Enterprise Admins|Schema Admins|BUILTIN\\Administrators") {
            $adminStatus.IsADAdmin = $true
        }
    }
    catch {
        Write-Warning "Error checking AD Admin status for $Username : $_"
    }

    # Check OUAdmin status (looking for OU-level permissions)
    try {
        $ouPermissions = Get-ADOrganizationalUnit -Filter * | ForEach-Object {
            Get-ACL "AD:$($_.DistinguishedName)" | ForEach-Object {
                $_.Access | Where-Object { 
                    $_.IdentityReference -like "*$Username*" -and 
                    $_.ActiveDirectoryRights -match "CreateChild|DeleteChild|WriteProperty"
                }
            }
        }
        if ($ouPermissions) {
            $adminStatus.IsOUAdmin = $true
        }
    }
    catch {
        Write-Warning "Error checking OU Admin status for $Username : $_"
    }

    # Return results
    return $adminStatus
}
