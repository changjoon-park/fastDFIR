function Get-ForestInventory {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "ForestInfo",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving comprehensive forest information..." -Level Info

        $forest = Invoke-WithRetry -ScriptBlock {
            Get-ADForest -ErrorAction Stop
        }

        $forestInfo = [PSCustomObject]@{
            ForestRootDomain   = $forest.RootDomain
            ForestMode         = $forest.ForestMode
            GlobalCatalogs     = $forest.GlobalCatalogs
            Domains            = $forest.Domains
            SchemaMaster       = $forest.SchemaMaster
            DomainNamingMaster = $forest.DomainNamingMaster
        }

        # Get detailed information using the separate functions
        # $trustInfo = Get-ADTrustInfo -RootDomain $forest.RootDomain # TODO: Root 도메인 말고..
        $domainInfo = Get-ADDomainInfo -DomainNames $forest.Domains
        $siteInfo = Get-ADSiteInfo
        $policyInfo = Get-ADPolicyInfo
        $networkTopology = Get-ADNetworkTopology
        $securityConfig = Get-ADSecurityConfiguration

        # Add the detailed information to the forest object
        $forestInfo | Add-Member -MemberType NoteProperty -Name Trusts -Value $trustInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name DomainInfo -Value $domainInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name Sites -Value $siteInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name Policies -Value $policyInfo
        $forestInfo | Add-Member -MemberType NoteProperty -Name NetworkTopology -Value $networkTopology
        $forestInfo | Add-Member -MemberType NoteProperty -Name SecurityConfiguration -Value $securityConfig

        Export-ADData -ObjectType $ObjectType -Data $forestInfo -ExportPath $ExportPath

        return $forestInfo
    }
    catch {
        Write-Log "Failed to retrieve forest information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve forest info."
        return $null
    }
}