function Get-ADOUInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainName
    )
    
    try {
        Write-Log "Retrieving OU information for domain: $DomainName..." -Level Info
        
        $ous = Get-ADOrganizationalUnit -Filter * -Server $DomainName -Properties * -ErrorAction Stop
        
        $ouInfo = foreach ($ou in $ous) {
            # Get ACL information
            $acl = Get-Acl -Path "AD:$($ou.DistinguishedName)" -ErrorAction SilentlyContinue
            
            # Process permissions
            $permissions = $acl.Access | ForEach-Object {
                [PSCustomObject]@{
                    IdentityReference     = $_.IdentityReference.ToString()
                    AccessControlType     = $_.AccessControlType.ToString()
                    ActiveDirectoryRights = $_.ActiveDirectoryRights.ToString()
                    InheritanceType       = $_.InheritanceType.ToString()
                }
            }
            
            [PSCustomObject]@{
                Name                 = $ou.Name
                DistinguishedName    = $ou.DistinguishedName
                Description          = $ou.Description
                Created              = $ou.Created
                Modified             = $ou.Modified
                ChildOUs             = ($ou.DistinguishedName -split ',OU=' | Select-Object -Skip 1) -join ',OU='
                DelegatedPermissions = $permissions
            }
        }
        
        return $ouInfo
    }
    catch {
        Write-Log "Error retrieving OU information for $DomainName : $($_.Exception.Message)" -Level Error
        return $null
    }
}