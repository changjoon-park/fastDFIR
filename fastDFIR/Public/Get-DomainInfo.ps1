function Get-DomainInfo {
    [CmdletBinding()]
    param()

    try {
        Write-Log "Retrieving domain information..." -Level Info
        $domain = Invoke-WithRetry -ScriptBlock {
            Get-ADDomain -ErrorAction Stop
        }
        Write-Host "===== Domain Information ====="
        $domain
        return $domain
    }
    catch {
        Write-Log "Failed to retrieve domain information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve domain info."
    }
}
