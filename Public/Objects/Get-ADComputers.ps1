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
            'IPv4Address',
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
            'ServicePrincipalNames',
            'MemberOf'  # Added MemberOf property
        )

        $computers = Invoke-WithRetry -ScriptBlock {
            Get-ADComputer -Filter * -Properties $properties -ErrorAction Stop
        }

        $computerObjects = Get-ADObjects -ObjectType $ObjectType -Objects $computers -ProcessingScript {
            param($computer)
            
            try {
                $computerObject = [PSCustomObject]@{
                    Name                   = $computer.Name
                    IPv4Address            = $computer.IPv4Address
                    DNSHostName            = $computer.DNSHostName
                    OperatingSystem        = $computer.OperatingSystem
                    OperatingSystemVersion = $computer.OperatingSystemVersion
                    Enabled                = $computer.Enabled
                    LastLogonDate          = $computer.LastLogonDate
                    Created                = $computer.Created
                    Modified               = $computer.Modified
                    DistinguishedName      = $computer.DistinguishedName
                    ServicePrincipalNames  = $computer.ServicePrincipalNames
                    MemberOf               = $computer.MemberOf  # Added MemberOf property
                    AccessStatus           = "Success"
                    NetworkStatus          = "Unknown"
                    IsAlive                = $false
                }

                # Updated ToString method to include group membership count
                Add-Member -InputObject $computerObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); NetworkStatus=$($this.NetworkStatus); IsAlive=$($this.IsAlive); Groups=$($this.MemberOf.Count)"
                } -Force

                $computerObject
            }
            catch {
                Write-Log "Error processing computer $($computer.Name): $($_.Exception.Message)" -Level Warning
                
                $computerObject = [PSCustomObject]@{
                    Name                   = $computer.Name
                    IPv4Address            = $null
                    DNSHostName            = $null
                    OperatingSystem        = $null
                    OperatingSystemVersion = $null
                    Enabled                = $null
                    LastLogonDate          = $null
                    Created                = $null
                    Modified               = $null
                    DistinguishedName      = $computer.DistinguishedName
                    ServicePrincipalNames  = $null
                    MemberOf               = @()  # Empty array for error cases
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                    NetworkStatus          = "Error"
                    IsAlive                = $false
                }

                Add-Member -InputObject $computerObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); NetworkStatus=Error; IsAlive=$($this.IsAlive); Groups=0"
                } -Force 

                $computerObject
            }
        }

        return $computerObjects
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve computer accounts. Check permissions."
    }
}