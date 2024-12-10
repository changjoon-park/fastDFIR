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
            Sites      = Get-ADSiteInfo
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

        # Final combined object
        $domainReport = [PSCustomObject]@{
            CollectionTime   = Get-Date
            BasicInfo        = $basicInfo
            DomainObjects    = $domainObjects
            SecuritySettings = $Security
            Infrastructure   = $Infrastructure
            # Statistics       = Get-CollectionStatistics -Data $domainObjects
        }

        # TODO: Implement Export-ADData function (Add-member to $domainReport)
        # Export-ADData -Data $domainReport -ExportPath $ExportPath

        return $domainReport
    }
    catch {
        Write-Log "Error in Get-DomainReport: $($_.Exception.Message)" -Level Error
        throw
    }
}