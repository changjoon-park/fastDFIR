function Get-ForestInfo {
    [CmdletBinding()]
    param()

    try {
        Write-Log "Retrieving forest information..." -Level Info
        $forest = Invoke-WithRetry -ScriptBlock {
            Get-ADForest -ErrorAction Stop
        }
        Write-Host "===== Forest Information ====="
        $forest
        return $forest
    }
    catch {
        Write-Log "Failed to retrieve forest information: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Insufficient permissions or unable to retrieve forest info."
    }
}
