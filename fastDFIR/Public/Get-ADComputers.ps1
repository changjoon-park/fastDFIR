function Get-ADComputers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
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
        
        $computers = Get-ADObjects -ObjectType "Computers" -Objects $allComputers -ProcessingScript {
            param($computer)
            $computer | Select-Object $properties
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType "Groups" -IncludeAccessStatus
        $stats.DisplayStatistics()

        # Export data if requested
        Export-ADData -ObjectType "Computers" -Data $computers -ExportPath $ExportPath -Export:$Export

        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "Computer retrieval complete" -Completed
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}
