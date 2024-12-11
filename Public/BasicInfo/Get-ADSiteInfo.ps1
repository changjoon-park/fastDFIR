function Get-ADSiteInfo {
    [CmdletBinding()]
    param()
    
    try {
        Write-Log "Retrieving AD site information..." -Level Info
        
        # Get all sites
        $sites = Get-ADReplicationSite -Filter * -ErrorAction SilentlyContinue | 
        ForEach-Object {
            $site = $_
            
            # Get subnets for this site
            $subnets = Get-ADReplicationSubnet -Filter "site -eq '$($site.DistinguishedName)'" | 
            ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Location    = $_.Location
                    Description = $_.Description
                }
            }
            
            # Create the site object with all information
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Created                = $site.Created
                Modified               = $site.Modified
                Subnets                = $subnets
                SiteLinks              = (Get-ADReplicationSiteLink -Filter *)
                ReplicationConnections = Get-ADReplicationConnection
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

        # Add ToString method to siteTopology
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