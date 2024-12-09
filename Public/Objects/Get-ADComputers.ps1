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
            'ServicePrincipalNames', # Added for role detection
            'Description',
            'Location',
            'primaryGroupID'          # To differentiate workstations/servers
        )
        
        $allComputers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computers = Get-ADObjects -ObjectType $ObjectType -Objects $allComputers -ProcessingScript {
            param($computer)
            
            try {
                # Determine computer type and roles
                $computerType = switch ($computer.primaryGroupID) {
                    515 { "Server" }
                    516 { "Workstation" }
                    default { "Unknown" }
                }

                # Parse SPNs to detect roles
                $roles = @()
                foreach ($spn in $computer.ServicePrincipalNames) {
                    switch -Regex ($spn) {
                        'DNS|host' { $roles += "DNS Server" }
                        'DHCP' { $roles += "DHCP Server" }
                        'CA' { $roles += "Certificate Authority" }
                        'MSSQL' { $roles += "SQL Server" }
                        'IISW3SVC' { $roles += "Web Server" }
                        'exchangeMDB' { $roles += "Exchange Server" }
                        'WSMAN' { $roles += "Windows Management" }
                        'FTP' { $roles += "FTP Server" }
                        'LDAP' { $roles += "Domain Controller" }
                        'RPCSS' { $roles += "RPC Server" }
                        'BITS' { $roles += "BITS Server" }
                    }
                }
                $roles = $roles | Select-Object -Unique

                # Check if it's a file server (attempt to get shares)
                if ($computerType -eq "Server") {
                    try {
                        $shares = Get-WmiObject -Class Win32_Share -ComputerName $computer.DNSHostName -ErrorAction Stop
                        if ($shares | Where-Object { $_.Type -eq 0 }) {
                            $roles += "File Server"
                        }
                    }
                    catch {
                        Write-Log "Unable to query shares on $($computer.Name): $($_.Exception.Message)" -Level Warning
                    }
                }

                # Get additional server features if possible
                if ($computerType -eq "Server") {
                    try {
                        $serverFeatures = Invoke-Command -ComputerName $computer.DNSHostName -ScriptBlock {
                            Get-WindowsFeature | Where-Object Installed
                        } -ErrorAction Stop
                        
                        foreach ($feature in $serverFeatures) {
                            $roles += "Windows Feature: $($feature.Name)"
                        }
                    }
                    catch {
                        Write-Log "Unable to query Windows features on $($computer.Name): $($_.Exception.Message)" -Level Warning
                    }
                }

                [PSCustomObject]@{
                    Name                       = $computer.Name
                    DNSHostName                = $computer.DNSHostName
                    ComputerType               = $computerType
                    OperatingSystem            = $computer.OperatingSystem
                    OperatingSystemVersion     = $computer.OperatingSystemVersion
                    OperatingSystemServicePack = $computer.OperatingSystemServicePack
                    Roles                      = $roles
                    Enabled                    = $computer.Enabled
                    LastLogonDate              = $computer.LastLogonDate
                    Created                    = $computer.Created
                    Modified                   = $computer.Modified
                    Description                = $computer.Description
                    Location                   = $computer.Location
                    DistinguishedName          = $computer.DistinguishedName
                    DomainJoined               = $true  # If it's in AD, it's domain-joined
                    AccessStatus               = "Success"
                }
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                       = $computer.Name
                    DNSHostName                = $null
                    ComputerType               = "Unknown"
                    OperatingSystem            = $null
                    OperatingSystemVersion     = $null
                    OperatingSystemServicePack = $null
                    Roles                      = @()
                    Enabled                    = $null
                    LastLogonDate              = $null
                    Created                    = $null
                    Modified                   = $null
                    Description                = $null
                    Location                   = $null
                    DistinguishedName          = $computer.DistinguishedName
                    DomainJoined               = $null
                    AccessStatus               = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $computers -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $computers -ExportPath $ExportPath
        
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}