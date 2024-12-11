function Get-ADTrustInfo {
    try {
        Write-Log "Retrieving AD trust information..." -Level Info
        
        $trustInfo = Get-ADTrust -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $info = [PSCustomObject]@{
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
            
            Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); Source=$($this.Source); Target=$($this.Target); TrustType=$($this.TrustType); Direction=$($this.Direction)"
            } -Force
            
            $info
        }

        return $trustInfo
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}
