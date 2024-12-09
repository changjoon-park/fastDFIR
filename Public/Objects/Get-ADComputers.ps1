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
        
        $allComputers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $computers = Get-ADObjects -ObjectType $ObjectType -Objects $allComputers -ProcessingScript {
            param($computer)
            
            try {
                # System Information via WMI
                $osInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $computer.DNSHostName -ErrorAction Stop
                $sysInfo = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $computer.DNSHostName -ErrorAction Stop
                $biosInfo = Get-WmiObject -Class Win32_BIOS -ComputerName $computer.DNSHostName -ErrorAction Stop
                
                # Services Status
                $services = Get-WmiObject -Class Win32_Service -ComputerName $computer.DNSHostName -ErrorAction Stop |
                Where-Object { $_.StartMode -eq 'Auto' } |
                Select-Object Name, State, StartMode, StartName
                
                # Network Configuration
                $networkConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $computer.DNSHostName -ErrorAction Stop |
                Where-Object { $_.IPEnabled -eq $true } |
                Select-Object IPAddress, DefaultIPGateway, DNSServerSearchOrder, MACAddress

                # Disk Information
                $diskInfo = Get-WmiObject -Class Win32_LogicalDisk -ComputerName $computer.DNSHostName -ErrorAction Stop |
                Where-Object { $_.DriveType -eq 3 } |
                Select-Object DeviceID, Size, FreeSpace

                # Startup Commands
                $startupCommands = Get-WmiObject -Class Win32_StartupCommand -ComputerName $computer.DNSHostName -ErrorAction Stop |
                Select-Object Command, Location, User

                # Share Information
                $shares = Get-WmiObject -Class Win32_Share -ComputerName $computer.DNSHostName -ErrorAction Stop |
                Select-Object Name, Path, Description

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

                    # System Details
                    LastBootUpTime         = $osInfo.ConvertToDateTime($osInfo.LastBootUpTime)
                    PhysicalMemory         = [math]::Round($sysInfo.TotalPhysicalMemory / 1GB, 2)
                    Manufacturer           = $sysInfo.Manufacturer
                    Model                  = $sysInfo.Model
                    BIOSVersion            = $biosInfo.Version
                    SerialNumber           = $biosInfo.SerialNumber

                    # Security Info
                    AutoStartServices      = $services
                    NetworkConfiguration   = $networkConfig
                    DiskInformation        = $diskInfo
                    StartupCommands        = $startupCommands
                    ShareInformation       = $shares

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
                    SID                    = $computer.SID
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
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