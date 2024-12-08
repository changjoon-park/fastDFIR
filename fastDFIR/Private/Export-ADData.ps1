function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectType, # e.g. "Users", "Groups", "Computers"
        
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Data, # The collection of objects to export
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath, # The directory to store the CSV
         
        [switch]$Export  # Whether to actually perform the export
    )

    if ($Export) {
        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')
        $exportFile = Join-Path $ExportPath ("{0}_{1}.csv" -f $ObjectType, $timestamp)
        $Data | Export-Csv $exportFile -NoTypeInformation
        Write-Log "$ObjectType exported to $exportFile" -Level Info
    }
}