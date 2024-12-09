function Get-ADOUInfo {
    
    try {
        Write-Log "Retrieving OU information for domain: $DomainName..." -Level Info
        
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * -ErrorAction Stop
        
        $ouInfo = foreach ($ou in $ous) {
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