function Get-ForestInventory {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "ForestInfo",
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving comprehensive forest information..." -Level Info

        # Retrieve forest info using a similar approach as previously demonstrated
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
            # You can add additional properties like Sites, Trusts, etc. here.
            # This is just a simplified example.
        }

        # If you have more detailed data (domains, trusts, sites), add them:
        # e.g.:
        # $forestInfo | Add-Member -MemberType NoteProperty -Name DomainInfo -Value $domainInfoObjects
        # $forestInfo | Add-Member -MemberType NoteProperty -Name Trusts -Value $trustObjects
        # $forestInfo | Add-Member -MemberType NoteProperty -Name Sites -Value $siteObjects
        # (Integration details as discussed previously.)

        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $forestInfo -ExportPath $ExportPath -Export:$Export

        return $forestInfo
    }
    catch {
        Write-Log "Failed to retrieve forest information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve forest info."
    }
}