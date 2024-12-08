function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectType,
        
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Data,
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath,
         
        [switch]$Export
    )

    if ($Export) {
        # Verify the export format is JSON
        if ($script:Config.DefaultExportFormat -ne "JSON") {
            Write-Log "Invalid export format specified in configuration. Defaulting to JSON." -Level Warning
        }

        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
        $exportFile = Join-Path $ExportPath ("{0}_{1}.json" -f $ObjectType, $timestamp)
        $Data | ConvertTo-Json -Depth 10 | Out-File $exportFile
        
        $fullPath = (Resolve-Path $exportFile).Path
        Write-Log "$ObjectType exported to $fullPath" -Level Info
    }
}