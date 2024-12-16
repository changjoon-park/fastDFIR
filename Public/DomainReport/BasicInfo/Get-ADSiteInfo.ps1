function Get-ADSiteInfo {
    [CmdletBinding()]
    param(
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving AD site information from AD..." -Level Info

        # Define the filter and properties for sites
        $filter = '*'
        $properties = @(
            'Name',
            'Description',
            'Location',
            'Created',
            'Modified',
            'DistinguishedName'
        )

        # Define the processing script for each site
        $processingScript = {
            param($site)

            # Retrieve subnets associated with the current site
            $subnets = Get-ADReplicationSubnet -Filter * -Credential $Credential | Where-Object {
                $_.Site -eq $site.DistinguishedName
            } | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    Location    = $_.Location
                    Description = $_.Description
                }
            }

            # Retrieve SiteLinks associated with the current site
            $siteLinks = Get-ADReplicationSiteLink -Filter * -Credential $Credential | Where-Object {
                $_.SitesIncluded -contains $site.Name
            } | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Name
                    LinkState   = $_.LinkState
                    Cost        = $_.Cost
                    Description = $_.Description
                }
            }

            # Retrieve Replication Connections associated with the current site
            $replConnections = Get-ADReplicationConnection -Filter * -Credential $Credential | Where-Object {
                $_.Site -eq $site.Name
            } | ForEach-Object {
                [PSCustomObject]@{
                    Name           = $_.Name
                    Partner        = $_.Partner
                    ConnectionType = $_.ConnectionType
                    Status         = $_.Status
                }
            }

            # Construct the site object with all retrieved information
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

        # Invoke the helper function to retrieve and process sites
        $sites = Invoke-ADRetrievalWithProgress -ObjectType "Sites" `
            -Filter $filter `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Sites"

        # Check if any sites were retrieved
        if (-not $sites) {
            Write-Log "No site information retrieved." -Level Warning
            return $null
        }

        # Create a summary object that includes overall topology information
        $siteTopology = [PSCustomObject]@{
            Sites                = $sites
            TotalSites           = ($sites | Measure-Object).Count
            TotalSubnets         = ($sites | ForEach-Object { $_.Subnets.Count } | Measure-Object -Sum).Sum
            TotalSiteLinks       = ($sites | ForEach-Object { $_.SiteLinks.Count } | Measure-Object -Sum).Sum
            TotalReplConnections = ($sites | ForEach-Object { $_.ReplicationConnections.Count } | Measure-Object -Sum).Sum
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