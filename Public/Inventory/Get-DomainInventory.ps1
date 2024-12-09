function Get-DomainInventory {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    if (-not (Initialize-Environment)) {
        Write-Log "Environment initialization failed" -Level Error
        return
    }
    
    $startTime = Get-Date
    Write-Log "Starting AD Inventory at $startTime" -Level Info
    
    try {
        # Domain Information
        $domainInfo = [PSCustomObject]@{
            ForestInfo = Get-ADForestInfo
            TrustInfo  = Get-ADTrustInfo
            DomainInfo = Get-ADDomainInfo
        }

        Export-ADData -Data $domainInfo -ExportPath $ExportPath

        # Domain Objects
        $domainObject = [PSCustomObject]@{
            ADUsers     = Get-ADUsers
            ADComputers = Get-ADComputers
            ADGroups    = Get-ADGroupsAndMembers
        }

        Export-ADData -Data $domainObject -ExportPath $ExportPath
    }
    catch {
        Write-Log "Error during inventory: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error during inventory process"
    }

    $endTime = Get-Date
    $duration = $endTime - $startTime
    Write-Log "AD Inventory completed. Duration: $($duration.TotalMinutes) minutes" -Level Info
}