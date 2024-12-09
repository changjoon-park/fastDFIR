function Get-ADDomainInfo {
    try {
        Write-Log "Retrieving AD domain information..." -Level Info
    
        $domain = Invoke-WithRetry -ScriptBlock {
            Get-ADDomain -ErrorAction Stop
        }

        # Try to get domain controllers
        $domainControllers = try {
            Get-ADDomainController -Filter * -ErrorAction Stop | 
            ForEach-Object {
                [PSCustomObject]@{
                    HostName               = $_.HostName
                    IPv4Address            = $_.IPv4Address
                    Site                   = $_.Site
                    IsGlobalCatalog        = $_.IsGlobalCatalog
                    OperatingSystem        = $_.OperatingSystem
                    OperatingSystemVersion = $_.OperatingSystemVersion
                    Enabled                = $_.Enabled
                }
            }
        }
        catch {
            Write-Log "Unable to retrieve domain controllers: $($_.Exception.Message)" -Level Warning
            "Access Denied or Connection Failed"
        }

        # Get OU information
        $ouInfo = Get-ADOUInfo 

        # Add this line after getting domain controllers
        $replicationInfo = Get-ADReplicationInfo 


        $domainInfo = [PSCustomObject]@{
            DomainName           = $domain.Name
            DomainMode           = $domain.DomainMode
            PDCEmulator          = $domain.PDCEmulator
            RIDMaster            = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            DomainControllers    = $domainControllers
            OrganizationalUnits  = $ouInfo
            ReplicationTopology  = $replicationInfo
        }

        return $domainInfo
    }
    catch {
        Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
        return $null
    }
}