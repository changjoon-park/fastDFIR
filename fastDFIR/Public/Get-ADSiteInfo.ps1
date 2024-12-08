function Get-ADSiteInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving AD site information..." -Level Info
        
        Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $site = $_
            $subnets = Get-ADReplicationSubnet -Filter * -ErrorAction SilentlyContinue | 
            Where-Object { $_.Site -eq $site.DistinguishedName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Site        = $_.Site
                    Location    = $_.Location
                    Description = $_.Description
                }
            }

            $siteLinks = Get-ADReplicationSiteLink -Filter * -ErrorAction SilentlyContinue |
            Where-Object { $_.Sites -contains $site.DistinguishedName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name                          = $_.Name
                    Cost                          = $_.Cost
                    ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
                    Sites                         = $_.Sites
                }
            }

            [PSCustomObject]@{
                SiteName    = $site.Name
                Description = $site.Description
                Location    = $site.Location
                Subnets     = $subnets
                SiteLinks   = $siteLinks
                Created     = $site.Created
                Modified    = $site.Modified
            }
        }
    }
    catch {
        Write-Log "Error retrieving site information: $($_.Exception.Message)" -Level Error
        return $null
    }
}
