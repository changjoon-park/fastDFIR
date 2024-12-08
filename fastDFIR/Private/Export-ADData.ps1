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
        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
        $exportFile = Join-Path $ExportPath ("{0}_{1}.json" -f $ObjectType, $timestamp)
        $fullPath = Convert-Path $exportFile
        $Data | ConvertTo-Json -Depth 10 | Out-File $exportFile

        Write-Log "$ObjectType exported to $fullPath" -Level Info
    }
}