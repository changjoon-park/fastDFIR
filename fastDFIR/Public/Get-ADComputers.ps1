function Get-ADComputers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Computers",
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
        
        $computers = Get-ADObjects -ObjectType $ObjectType -Objects $allComputers -ProcessingScript {
            param($computer)
            
            try {
                [PSCustomObject]@{
                    Name                   = $computer.Name
                    OperatingSystem        = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    Enabled                = $computer.Enabled
                    LastLogonDate          = $computer.LastLogonDate
                    Created                = $computer.Created
                    Modified               = $computer.Modified
                    DNSHostName            = $computer.DNSHostName
                    DistinguishedName      = $computer.DistinguishedName
                    AccessStatus           = "Success"
                }
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                   = $computer.Name
                    OperatingSystem        = $null
                    OperatingSystemVersion = $null
                    Enabled                = $null
                    LastLogonDate          = $null
                    Created                = $null
                    Modified               = $null
                    DNSHostName            = $null
                    DistinguishedName      = $computer.DistinguishedName
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $computers -ExportPath $ExportPath
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "Computer retrieval complete" -Completed
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}