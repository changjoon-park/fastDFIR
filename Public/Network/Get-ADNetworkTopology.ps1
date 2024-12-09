function Get-ADNetworkTopology {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "NetworkTopology",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving network topology information..." -Level Info
        
        # Get Sites and Subnets
        $siteInfo = Get-ADSiteTopology
        
        # Get DNS Zones
        $dnsInfo = Get-ADDNSInfo
        
        $networkTopology = [PSCustomObject]@{
            Sites    = $siteInfo
            DNSZones = $dnsInfo
        }
        
        # Export data
        Export-ADData -ObjectType $ObjectType -Data $networkTopology -ExportPath $ExportPath
        
        return $networkTopology
    }
    catch {
        Write-Log "Error retrieving network topology: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve network topology information. Check permissions."
    }
}

function Get-ADSiteTopology {
    [CmdletBinding()]
    param()
    
    try {
        $sites = Get-ADReplicationSite -Filter * | ForEach-Object {
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
            $siteLinks = Get-ADReplicationSiteLink -Filter * |
            Where-Object { $_.Sites -contains $site.DistinguishedName } |
            ForEach-Object {
                [PSCustomObject]@{
                    Name                 = $_.Name
                    Cost                 = $_.Cost
                    ReplicationFrequency = $_.ReplicationFrequencyInMinutes
                    Schedule             = $_.ReplicationSchedule
                    Sites                = $_.Sites | ForEach-Object {
                        (Get-ADObject $_ -Properties Name).Name
                    }
                    Options              = $_.Options
                }
            }
            
            # Get replication connections
            $replConnections = Get-ADReplicationConnection -Filter "FromServer -like '*$($site.Name)*' -or ToServer -like '*$($site.Name)*'" |
            ForEach-Object {
                [PSCustomObject]@{
                    FromServer = $_.FromServer
                    ToServer   = $_.ToServer
                    Schedule   = $_.Schedule
                    Options    = $_.Options
                }
            }
            
            [PSCustomObject]@{
                Name                   = $site.Name
                Description            = $site.Description
                Location               = $site.Location
                Subnets                = $subnets
                SiteLinks              = $siteLinks
                ReplicationConnections = $replConnections
            }
        }
        
        return $sites
    }
    catch {
        Write-Log "Error retrieving site topology: $($_.Exception.Message)" -Level Error
        return $null
    }
}

