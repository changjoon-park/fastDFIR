function Get-ADDomainInfo {
    <#
    .SYNOPSIS
    Retrieves Active Directory domain information, including domain controllers.
    
    .DESCRIPTION
    The Get-ADDomainInfo function gathers domain-level information, including details about the domain itself and its domain controllers. It returns a structured object containing key domain properties and related data.
    
    .PARAMETER Credential
    (Mandatory) PSCredential object representing the user account with sufficient privileges to access AD information.
    
    .EXAMPLE
    $cred = Get-Credential -Message "Enter AD Admin credentials"
    $domainInfo = Get-ADDomainInfo -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        try {
            Write-Log "Retrieving AD domain information..." -Level Info

            # Define the processing script for domain information
            $domainProcessingScript = {
                param($domain)

                [PSCustomObject]@{
                    DomainName           = $domain.Name
                    DomainMode           = $domain.DomainMode
                    PDCEmulator          = $domain.PDCEmulator
                    RIDMaster            = $domain.RIDMaster
                    InfrastructureMaster = $domain.InfrastructureMaster
                } | Add-Member -MemberType ScriptMethod -Name "ToString" -Value {
                    "DomainName=$($this.DomainName); DomainMode=$($this.DomainMode); PDCEmulator=$($this.PDCEmulator); InfrastructureMaster=$($this.InfrastructureMaster)"
                } -Force
            }

            # Retrieve DomainInfo
            $domainInfo = Invoke-ADRetrievalWithProgress -ObjectType "DomainInfo" `
                -Filter '*' `
                -Properties @('Name', 'DomainMode', 'PDCEmulator', 'RIDMaster', 'InfrastructureMaster') `
                -Credential $Credential `
                -ProcessingScript $domainProcessingScript `
                -ActivityName "Retrieving Domain Information"

            if (-not $domainInfo) {
                Write-Log "Failed to retrieve Domain Information." -Level Error
                return $null
            }

            # Define the processing script for Domain Controllers
            $dcProcessingScript = {
                param($dc)

                [PSCustomObject]@{
                    HostName               = $dc.Name
                    IPv4Address            = $dc.IPv4Address
                    Site                   = $dc.Site
                    IsGlobalCatalog        = $dc.IsGlobalCatalog
                    OperatingSystem        = $dc.OperatingSystem
                    OperatingSystemVersion = $dc.OperatingSystemVersion
                    Enabled                = $dc.Enabled
                } | Add-Member -MemberType ScriptMethod -Name "ToString" -Value {
                    "HostName=$($this.HostName); IPv4=$($this.IPv4Address); Site=$($this.Site)"
                } -PassThru
            }

            # Retrieve Domain Controllers
            $domainControllers = Invoke-ADRetrievalWithProgress -ObjectType "DomainControllers" `
                -Filter '*' `
                -Properties @('Name', 'IPv4Address', 'Site', 'IsGlobalCatalog', 'OperatingSystem', 'OperatingSystemVersion', 'Enabled') `
                -Credential $Credential `
                -ProcessingScript $dcProcessingScript `
                -ActivityName "Retrieving Domain Controllers"

            if (-not $domainControllers) {
                Write-Log "Failed to retrieve Domain Controllers." -Level Warning
                $domainControllers = @()
            }

            # Combine DomainInfo and DomainControllers into a single object
            $combinedDomainInfo = [PSCustomObject]@{
                DomainName           = $domainInfo.DomainName
                DomainMode           = $domainInfo.DomainMode
                PDCEmulator          = $domainInfo.PDCEmulator
                RIDMaster            = $domainInfo.RIDMaster
                InfrastructureMaster = $domainInfo.InfrastructureMaster
                DomainControllers    = $domainControllers
            }

            # Add ToString method to combinedDomainInfo for better readability
            $combinedDomainInfo | Add-Member -MemberType ScriptMethod -Name "ToString" -Value {
                "DomainName=$($this.DomainName); DomainMode=$($this.DomainMode); InfrastructureMaster=$($this.InfrastructureMaster); DCs=$($this.DomainControllers.Count)"
            } -Force

            Write-Log "Successfully retrieved AD domain information with Domain Controllers." -Level Info
            return $combinedDomainInfo
        }
        catch {
            Write-Log "Error in Get-ADDomainInfo: $($_.Exception.Message)" -Level Error
            return $null
        }
    }
}


#region Get-ADOUInfo.ps1

function Get-ADOUInfo {
    <#
    .SYNOPSIS
    Retrieves Organizational Unit (OU) information from Active Directory.

    .DESCRIPTION
    The Get-ADOUInfo function gathers information about Organizational Units (OUs) within the Active Directory. It returns a collection of structured objects containing OU properties.

    .PARAMETER Credential
    (Mandatory) PSCredential object representing the user account with sufficient privileges to access AD information.

    .EXAMPLE
    $cred = Get-Credential -Message "Enter AD Admin credentials"
    $ouInfo = Get-ADOUInfo -Credential $cred
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential
    )

    process {
        try {
            Write-Log "Retrieving Organizational Unit (OU) information..." -Level Info

            # Define the processing script for OUs
            $processingScript = {
                param($ou)

                [PSCustomObject]@{
                    Name              = $ou.Name
                    DistinguishedName = $ou.DistinguishedName
                    Description       = $ou.Description
                    Created           = $ou.Created
                    Modified          = $ou.Modified
                    ChildOUs          = ($ou.DistinguishedName -split ',OU=' | Select-Object -Skip 1) -join ',OU='
                } | Add-Member -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); Children=$($this.ChildOUs.Split(',').Count)"
                } -Force
            }

            # Invoke the helper function
            $ouInfo = Invoke-ADRetrievalWithProgress -ObjectType "OrganizationalUnits" `
                -Filter '*' `
                -Properties @('Name', 'DistinguishedName', 'Description', 'Created', 'Modified') `
                -Credential $Credential `
                -ProcessingScript $processingScript `
                -ActivityName "Retrieving Organizational Units"

            return $ouInfo
        }
        catch {
            Write-Log "Error in Get-ADOUInfo: $($_.Exception.Message)" -Level Error
            return $null
        }
    }
}
