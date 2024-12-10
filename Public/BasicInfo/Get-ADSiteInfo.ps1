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
            
            # Get site links
            $siteLinks = Get-ADReplicationSiteLink -Filter *
            # $siteLinks = Get-ADReplicationSiteLink -Filter * |
            # Where-Object { $_.Sites -contains $site.DistinguishedName } |
            # ForEach-Object {
            #     [PSCustomObject]@{
            #         Name                          = $_.Name
            #         Cost                          = $_.Cost
            #         ReplicationFrequencyInMinutes = $_.ReplicationFrequencyInMinutes
            #         Schedule                      = $_.ReplicationSchedule
            #         Sites                         = $_.Sites | ForEach-Object {
            #             (Get-ADObject $_ -Properties Name).Name
            #         }
            #         Options                       = $_.Options
            #     }
            # }
            
            # Get replication connections
            $replConnections = Get-ADReplicationConnection
            # $replConnections = Get-ADReplicationConnection -Filter "FromServer -like '*$($site.Name)*' -or ToServer -like '*$($site.Name)*'" |
            # ForEach-Object {
            #     [PSCustomObject]@{
            #         FromServer = $_.FromServer
            #         ToServer   = $_.ToServer
            #         Schedule   = $_.Schedule
            #         Options    = $_.Options
            #     }
            # }

            # Create the site object with all information
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Created                = $site.Created
                Modified               = $site.Modified
                Subnets                = $subnets
                SiteLinks              = $siteLinks
                ReplicationConnections = $replConnections
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

        return $siteTopology
    }
    catch {
        Write-Log "Error retrieving site information: $($_.Exception.Message)" -Level Error
        return $null
    }
}