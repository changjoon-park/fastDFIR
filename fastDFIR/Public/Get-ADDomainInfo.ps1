function Get-ADDomainInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$DomainNames
    )
    
    try {
        Write-Log "Retrieving AD domain information..." -Level Info
        
        $results = foreach ($domainName in $DomainNames) {
            try {
                Write-Log "Attempting to access domain: $domainName" -Level Info
                
                $domain = Invoke-WithRetry -ScriptBlock {
                    Get-ADDomain -Identity $domainName -ErrorAction Stop
                }

                # Try to get domain controllers
                $domainControllers = try {
                    Get-ADDomainController -Filter "Domain -eq '$domainName'" -ErrorAction Stop | 
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
                    Write-Log "Unable to retrieve domain controllers for $domainName : $($_.Exception.Message)" -Level Warning
                    "Access Denied or Connection Failed"
                }

                [PSCustomObject]@{
                    DomainName           = $domainName
                    DomainMode           = $domain.DomainMode
                    PDCEmulator          = $domain.PDCEmulator
                    RIDMaster            = $domain.RIDMaster
                    InfrastructureMaster = $domain.InfrastructureMaster
                    DomainControllers    = $domainControllers
                    AccessStatus         = "Success"
                }
            }
            catch {
                Write-Log "Failed to access domain $domainName : $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    DomainName           = $domainName
                    DomainMode           = $null
                    PDCEmulator          = $null
                    RIDMaster            = $null
                    InfrastructureMaster = $null
                    DomainControllers    = @()
                    AccessStatus         = "Access Failed: $($_.Exception.Message)"
                }
            }
        }

        return $results
    }
    catch {
        Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
        return $null
    }
}