function Get-ADComputers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Computers",
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving computer accounts from AD..." -Level Info

        # Build parameters for counting and retrieving computers
        $countParams = @{ Filter = '*' }
        $getParams = @{ 
            Filter     = '*'
            Properties = 'IPv4Address', 'DistinguishedName', 'OperatingSystem', 'OperatingSystemVersion', 'Enabled', 'LastLogonDate', 'Created', 'Modified', 'DNSHostName', 'SID', 'ServicePrincipalNames', 'MemberOf'
        }

        if ($Credential) {
            $countParams.Credential = $Credential
            $getParams.Credential = $Credential
        }

        Write-Log "Counting total computers for progress calculation..." -Level Info
        $total = (Get-ADComputer @countParams | Measure-Object).Count
        if ($total -eq 0) {
            Write-Log "No computer accounts found in the domain." -Level Warning
            return $null
        }

        Write-Log "Retrieving and processing $total computer accounts..." -Level Info

        $count = 0
        $computers = Get-ADComputer @getParams |
        ForEach-Object -Begin {
            Show-Progress -Activity "Retrieving Computers" -Status "Starting..." -PercentComplete 0
        } -Process {
            $count++
            try {
                # Construct the custom object with desired properties
                $computerObject = [PSCustomObject]@{
                    Name                   = $_.Name
                    IPv4Address            = $_.IPv4Address
                    DNSHostName            = $_.DNSHostName
                    OperatingSystem        = $_.OperatingSystem
                    OperatingSystemVersion = $_.OperatingSystemVersion
                    Enabled                = $_.Enabled
                    LastLogonDate          = $_.LastLogonDate
                    Created                = $_.Created
                    Modified               = $_.Modified
                    DistinguishedName      = $_.DistinguishedName
                    ServicePrincipalNames  = $_.ServicePrincipalNames
                    MemberOf               = $_.MemberOf
                    AccessStatus           = "Success"
                    NetworkStatus          = "Unknown"
                    IsAlive                = $false
                }

                Add-Member -InputObject $computerObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); NetworkStatus=$($this.NetworkStatus); IsAlive=$($this.IsAlive); Groups=$($this.MemberOf.Count)"
                } -Force

                # Update progress
                $percent = [int](($count / $total) * 100)
                Show-Progress -Activity "Retrieving Computers" -Status "Processing computer $count of $total" -PercentComplete $percent
                $computerObject
            }
            catch {
                Write-Log "Error processing computer $($_.Name): $($_.Exception.Message)" -Level Warning
                $errorObject = [PSCustomObject]@{
                    Name                   = $_.Name
                    IPv4Address            = $null
                    DNSHostName            = $null
                    OperatingSystem        = $null
                    OperatingSystemVersion = $null
                    Enabled                = $null
                    LastLogonDate          = $null
                    Created                = $null
                    Modified               = $null
                    DistinguishedName      = $_.DistinguishedName
                    ServicePrincipalNames  = $null
                    MemberOf               = @()
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                    NetworkStatus          = "Error"
                    IsAlive                = $false
                }

                Add-Member -InputObject $errorObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); NetworkStatus=Error; IsAlive=$($this.IsAlive); Groups=0"
                } -Force

                $errorObject
            }
        } -End {
            Show-Progress -Activity "Retrieving Computers" -Completed
        }

        Write-Log "Successfully retrieved $($computers.Count) computer accounts." -Level Info
        return $computers
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
    }
}