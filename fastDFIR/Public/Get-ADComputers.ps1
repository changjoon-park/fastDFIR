function Get-ADComputers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Computers",
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath,
        [Parameter()]
        [ValidateSet("JSON", "CSV")]
        [string]$ExportType = "JSON" # Default export type is JSON
    )
    
    try {
        Write-Log "Retrieving computer accounts..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing computer retrieval..."
        
        $properties = @(
            'Name',
            'DistinguishedName',
            'OperatingSystem',
            'OperatingSystemVersion',
            'Enabled',
            'LastLogonDate',
            'Created',
            'Modified',
            'DNSHostName'
        )
        
        $allComputers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computers = Get-ADObjects -ObjectType $ObjectTypej -Objects $allComputers -ProcessingScript {
            param($computer)
            $computer | Select-Object $properties
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType $ObjectTypej -IncludeAccessStatus
        $stats.DisplayStatistics()

        # Export data if requested
        Export-ADData -ObjectType $ObjectTypej -Data $computers -ExportPath $ExportPath -Export:$Export -ExportType $ExportType

        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "Computer retrieval complete" -Completed
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}
