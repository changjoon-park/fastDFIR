function Get-ADDomainInfo {
    try {
        Write-Log "Retrieving AD domain information from cached data..." -Level Info
    
        if (-not $script:Domain) {
            Write-Log "Domain data not available in cache." -Level Warning
            return $null
        }

        # If domain controllers are not available, handle it gracefully
        $domainControllers = $null
        if ($script:AllDCs) {
            $domainControllers = @()
            foreach ($dcItem in $script:AllDCs) {
                $dc = [PSCustomObject]@{
                    HostName               = $dcItem.HostName
                    IPv4Address            = $dcItem.IPv4Address
                    Site                   = $dcItem.Site
                    IsGlobalCatalog        = $dcItem.IsGlobalCatalog
                    OperatingSystem        = $dcItem.OperatingSystem
                    OperatingSystemVersion = $dcItem.OperatingSystemVersion
                    Enabled                = $dcItem.Enabled
                }

                Add-Member -InputObject $dc -MemberType ScriptMethod -Name "ToString" -Value {
                    "HostName=$($this.HostName); IPv4=$($this.IPv4Address); Site=$($this.Site)"
                } -Force

                $domainControllers += $dc
            }
        }
        else {
            Write-Log "No cached domain controller data found." -Level Warning
            $domainControllers = "Access Denied or Connection Failed"
        }

        $ouInfo = Get-ADOUInfo  # Now uses cached $script:AllOUs

        $domainInfo = [PSCustomObject]@{
            DomainName           = $script:Domain.Name
            DomainMode           = $script:Domain.DomainMode
            PDCEmulator          = $script:Domain.PDCEmulator
            RIDMaster            = $script:Domain.RIDMaster
            InfrastructureMaster = $script:Domain.InfrastructureMaster
            DomainControllers    = $domainControllers
            OrganizationalUnits  = $ouInfo
        }

        # Add ToString method to domainInfo
        Add-Member -InputObject $domainInfo -MemberType ScriptMethod -Name "ToString" -Value {
            "DomainName=$($this.DomainName); DomainMode=$($this.DomainMode); PDCEmulator=$($this.PDCEmulator); InfrastructureMaster=$($this.InfrastructureMaster); DCs=$($this.DomainControllers.Count); OUs=$($this.OrganizationalUnits.Count)"
        } -Force

        return $domainInfo
    }
    catch {
        Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-ADOUInfo {
    try {
        Write-Log "Retrieving OU information from cached data..." -Level Info
        
        if (-not $script:AllOUs) {
            Write-Log "No OU data available in cache." -Level Warning
            return $null
        }

        $ouInfo = @()
        foreach ($ou in $script:AllOUs) {
            $ouObject = [PSCustomObject]@{
                Name              = $ou.Name
                DistinguishedName = $ou.DistinguishedName
                Description       = $ou.Description
                Created           = $ou.Created
                Modified          = $ou.Modified
                ChildOUs          = ($ou.DistinguishedName -split ',OU=' | Select-Object -Skip 1) -join ',OU='
            }

            # Add ToString method to each OU object
            Add-Member -InputObject $ouObject -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); Children=$($this.ChildOUs.Split(',').Count)"
            } -Force

            $ouInfo += $ouObject
        }
        
        return $ouInfo
    }
    catch {
        Write-Log "Error retrieving OU information: $($_.Exception.Message)" -Level Error
        return $null
    }
}