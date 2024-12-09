function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Data, 
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath
    )

    # Verify the export format is JSON
    if ($script:Config.DefaultExportFormat -ne "JSON") {
        Write-Log "Invalid export format specified in configuration. Defaulting to JSON." -Level Warning
    }
    
    if (-not (Test-Path $ExportPath)) {
        New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
    }
    
    $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
    $exportFile = Join-Path $ExportPath ("DomainInventory_{1}.json" -f $timestamp)
    
    # If $Data is not an array, just wrap it in one before converting to JSON
    if ($Data -isnot [System.Collections.IEnumerable] -or $Data -is [string]) {
        $Data = @($Data)
    }
    
    $Data | ConvertTo-Json -Depth 10 | Out-File $exportFile
    
    $fullPath = (Resolve-Path $exportFile).Path
    Write-Log "Domain Inventory exported to $fullPath" -Level Info
}