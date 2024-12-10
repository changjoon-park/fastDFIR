function Get-ADForestInfo {
    try {
        Write-Log "Retrieving AD forest information..." -Level Info
        
        $forestInfo = Get-ADForest -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $info = [PSCustomObject]@{
                Name                = $_.Name
                ForestMode          = $_.ForestMode
                SchemaMaster        = $_.SchemaMaster
                DomainNamingMaster  = $_.DomainNamingMaster
                GlobalCatalogs      = $_.GlobalCatalogs
                Sites               = $_.Sites
                Domains             = $_.Domains
                RootDomain          = $_.RootDomain
                SchemaNamingContext = $_.SchemaNamingContext
                DistinguishedName   = $_.DistinguishedName
            }
            
            # Add ToString method
            Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); ForestMode=$($this.ForestMode); SchemaMaster=$($this.SchemaMaster); GlobalCatalogs=$($this.GlobalCatalogs.Count); Domains=$($this.Domains.Count)"
            }
            
            $info
        }

        return $forestInfo
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}