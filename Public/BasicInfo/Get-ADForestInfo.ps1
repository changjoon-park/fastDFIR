function Get-ADForestInfo {
    try {
        Write-Log "Retrieving AD forest information from cached data..." -Level Info

        if (-not $script:ForestInfo) {
            Write-Log "No forest information available in cache." -Level Warning
            return $null
        }

        $info = [PSCustomObject]@{
            Name                = $script:ForestInfo.Name
            ForestMode          = $script:ForestInfo.ForestMode
            SchemaMaster        = $script:ForestInfo.SchemaMaster
            DomainNamingMaster  = $script:ForestInfo.DomainNamingMaster
            GlobalCatalogs      = $script:ForestInfo.GlobalCatalogs
            Sites               = $script:ForestInfo.Sites
            Domains             = $script:ForestInfo.Domains
            RootDomain          = $script:ForestInfo.RootDomain
            SchemaNamingContext = $script:ForestInfo.SchemaNamingContext
            DistinguishedName   = $script:ForestInfo.DistinguishedName
        }
            
        Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
            "Name=$($this.Name); ForestMode=$($this.ForestMode); SchemaMaster=$($this.SchemaMaster); GlobalCatalogs=$($this.GlobalCatalogs.Count); Domains=$($this.Domains.Count)"
        } -Force
        
        return $info
    }
    catch {
        Write-Log "Error retrieving forest information: $($_.Exception.Message)" -Level Error
        return $null
    }
}