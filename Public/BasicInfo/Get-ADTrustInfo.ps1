function Get-ADTrustInfo {
    try {
        Write-Log "Retrieving AD trust information..." -Level Info
        
        Get-ADTrust -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            [PSCustomObject]@{
                Name               = $_.Name
                Source             = $_.Source
                Target             = $_.Target
                TrustType          = $_.TrustType
                Direction          = $_.Direction
                DisallowTransivity = $_.DisallowTransivity
                InstraForest       = $_.InstraForest
                TGTQuota           = $_.TGTQuota
                DistinguishedName  = $_.DistinguishedName
            }
        }
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}
