function Get-ADSiteInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving AD site information from cached data..." -Level Info
        
        # Use cached AllSites data instead of re-querying AD
        $sites = foreach ($site in $script:AllSites) {
            # Filter subnets that belong to this site using the cached AllSubnets
            $subnets = $script:AllSubnets | Where-Object {
                # Assuming each subnet object has a 'Site' property that references the site DN
                $_.Site -eq $site.DistinguishedName
            } | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Location    = $_.Location
                    Description = $_.Description
                }
            }

            # Create the site object with all information using cached data
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Created                = $site.Created
                Modified               = $site.Modified
                Subnets                = $subnets

                # SiteLinks and ReplicationConnections were previously retrieved and stored
                # If you need them per site, consider filtering them by a site-related property
                SiteLinks              = $script:AllSiteLinks
                ReplicationConnections = $script:AllReplConnections
                DistinguishedName      = $site.DistinguishedName
            }
        }

        # Create a summary object that includes overall topology information
        $siteTopology = [PSCustomObject]@{
            Sites                = $sites
            TotalSites           = ($sites | Measure-Object).Count
            TotalSubnets         = ($sites.Subnets | Measure-Object).Count
            TotalSiteLinks       = ($sites.SiteLinks | Sort-Object -Property Name -Unique | Measure-Object).Count
            TotalReplConnections = ($sites.ReplicationConnections | Measure-Object).Count
        }

        # Add a ToString method to siteTopology
        Add-Member -InputObject $siteTopology -MemberType ScriptMethod -Name "ToString" -Value {
            "Sites=$($this.Sites.Count); TotalSites=$($this.TotalSites); TotalSubnets=$($this.TotalSubnets); TotalSiteLinks=$($this.TotalSiteLinks); TotalReplConnections=$($this.TotalReplConnections)"
        } -Force

        return $siteTopology
    }
    catch {
        Write-Log "Error retrieving site information: $($_.Exception.Message)" -Level Error
        return $null
    }
}