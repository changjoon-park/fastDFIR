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

        $domainInfo = [PSCustomObject]@{
            DomainName           = $domain.Name
            DomainMode           = $domain.DomainMode
            PDCEmulator          = $domain.PDCEmulator
            RIDMaster            = $domain.RIDMaster
            InfrastructureMaster = $domain.InfrastructureMaster
            DomainControllers    = $domainControllers
            OrganizationalUnits  = Get-ADOUInfo
        }

        # Add ToString method to domainInfo
        Add-Member -InputObject $domainInfo -MemberType ScriptMethod -Name "ToString" -Value {
            "DomainName=$($this.DomainName); DomainMode=$($this.DomainMode); PDCEmulator=$($this.PDCEmulator); InfrastructureMaster=$($this.InfrastructureMaster); DCs=$($this.DomainControllers.Count); OUs=$($this.OrganizationalUnits.Count)"
        }

        return $domainInfo
    }
    catch {
        Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
        return $null
    }
}

function Get-ADOUInfo {
    try {
        Write-Log "Retrieving OU information for domain:..." -Level Info
        
        $ous = Get-ADOrganizationalUnit -Filter * -Properties * -ErrorAction Stop
        
        $ouInfo = foreach ($ou in $ous) {
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
                "Name=$($this.Name); DN=$($this.DistinguishedName); Children=$($this.ChildOUs.Split(',').Count)"
            }

            $ouObject
        }
        
        return $ouInfo
    }
    catch {
        Write-Log "Error retrieving OU information for: $($_.Exception.Message)" -Level Error
        return $null
    }
}