#region Get-ADComputers.ps1

function Get-ADComputers {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving computer accounts from AD..." -Level Info

        # Define the properties to retrieve
        $properties = @(
            'IPv4Address',
            'DistinguishedName',
            'OperatingSystem',
            'OperatingSystemVersion',
            'Enabled',
            'LastLogonDate',
            'Created',
            'Modified',
            'DNSHostName',
            'SID',
            'ServicePrincipalNames',
            'MemberOf'
        )

        # Define the processing script for each computer
        $processingScript = {
            param($computer)

            # Construct the custom object with desired properties
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
                MemberOf               = $computer.MemberOf
                AccessStatus           = "Success"
                NetworkStatus          = "Unknown"
                IsAlive                = $false
            }

            # Add a ToString method for better readability
            Add-Member -InputObject $computerObject -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); NetworkStatus=$($this.NetworkStatus); IsAlive=$($this.IsAlive); Groups=$($this.MemberOf.Count)"
            } -Force

            $computerObject
        }

        # Invoke the helper function
        return Invoke-ADRetrievalWithProgress -ObjectType "Computers" `
            -Filter '*' `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Computers"
    }
    catch {
        Write-Log "Error retrieving computers: $($_.Exception.Message)" -Level Error
    }
}

#endregion