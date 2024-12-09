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
            'OperatingSystemServicePack',
            'Enabled',
            'LastLogonDate',
            'Created',
            'Modified',
            'DNSHostName',
            'SID',
            'ServicePrincipalNames'  # Added for service detection
        )
        
        $computers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computerObjects = Get-ADObjects -ObjectType $ObjectType -Objects $computers -ProcessingScript {
            param($computer)
            
            try {
                # $serviceTypes = @(foreach ($spn in $computer.ServicePrincipalNames) {
                #         switch -Regex ($spn) {
                #             'MSSQL' { 'SQL Server' }
                #             'exchangeMDB' { 'Exchange' }
                #             'WWW|HTTP' { 'Web Server' }
                #             'FTP' { 'FTP Server' }
                #             'SMTP' { 'SMTP Server' }
                #             'DNS' { 'DNS Server' }
                #             'LDAP' { 'Domain Controller' }
                #         }
                #     } | Select-Object -Unique)

                [PSCustomObject]@{
                    # Basic AD Info
                    Name                   = $computer.Name
                    DNSHostName            = $computer.DNSHostName
                    OperatingSystem        = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    Enabled                = $computer.Enabled
                    LastLogonDate          = $computer.LastLogonDate
                    Created                = $computer.Created
                    Modified               = $computer.Modified
                    DistinguishedName      = $computer.DistinguishedName
                    ServicePrincipalNames  = $computer.ServicePrincipalNames
                    AccessStatus           = "Success"
                }
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                   = $computer.Name
                    DNSHostName            = $computer.DNSHostName
                    OperatingSystem        = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    Enabled                = $computer.Enabled
                    LastLogonDate          = $computer.LastLogonDate
                    Created                = $computer.Created
                    Modified               = $computer.Modified
                    DistinguishedName      = $computer.DistinguishedName
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        return $computerObjects
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}