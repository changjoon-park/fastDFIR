function Export-ADData {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ObjectType, # e.g. "Users", "Groups", "Computers"
        
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Data, # The collection of objects to export
        
        [Parameter(Mandatory = $true)]
        [string]$ExportPath, # The directory to store the file
         
        [switch]$Export, # Whether to actually perform the export

        [Parameter()]
        [ValidateSet("JSON", "CSV")]
        [string]$ExportType = "JSON" # Default export type is JSON
    )

    if ($Export) {
        if (-not (Test-Path $ExportPath)) {
            New-Item -ItemType Directory -Path $ExportPath -Force | Out-Null
        }

        $timestamp = (Get-Date -Format 'yyyyMMdd_HHmmss')

        switch ($ExportType) {
            "CSV" {
                $exportFile = Join-Path $ExportPath ("{0}_{1}.csv" -f $ObjectType, $timestamp)
                $Data | Export-Csv $exportFile -NoTypeInformation
            }
            "JSON" {
                $exportFile = Join-Path $ExportPath ("{0}_{1}.json" -f $ObjectType, $timestamp)
                $Data | ConvertTo-Json -Depth 5 | Out-File $exportFile -Encoding UTF8
            }
        }

        Write-Log "$ObjectType exported to $($exportFile.FullName) (Type: $ExportType)" -Level Info
    }
}