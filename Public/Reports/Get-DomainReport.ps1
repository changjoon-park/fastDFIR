function Get-DomainReport {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath
    )

    try {
        # Basic Domain Information
        $basicInfo = [PSCustomObject]@{
            ForestInfo = Get-ADForestInfo
            TrustInfo  = Get-ADTrustInfo
            DomainInfo = Get-ADDomainInfo
        }

        # Domain Objects Information
        $domainObjects = [PSCustomObject]@{
            Users     = Get-ADUsers
            Computers = Get-ADComputers
            Groups    = Get-ADGroupsAndMembers
        }

        # Security Configuration
        $Security = [PSCustomObject]@{
            # Policies           = Get-ADPolicyInfo # TODO: Permission Denied
            SecurityConfig = Get-ADSecurityConfiguration
        }

        # Infrastructure Information
        $Infrastructure = [PSCustomObject]@{
            Sites = Get-ADSiteInfo
            # DNSInfo         = Get-ADDNSInfo  # TODO: Permission Denied
        }

        # Final combined object
        $domainInformation = [PSCustomObject]@{
            CollectionTime   = Get-Date
            BasicInformation = $basicInfo
            DomainObjects    = $domainObjects
            SecuritySettings = $Security
            Infrastructure   = $Infrastructure
            # Statistics       = Get-CollectionStatistics -Data $domainObjects
        }

        # Export if requested
        Export-ADData -Data $domainInformation -ExportPath $ExportPath

        return $domainInformation
    }
    catch {
        Write-Log "Error in Get-DomainInformation: $($_.Exception.Message)" -Level Error
        throw
    }
}