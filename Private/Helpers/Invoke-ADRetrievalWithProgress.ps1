#region Invoke-ADRetrievalWithProgress.ps1

function Invoke-ADRetrievalWithProgress {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateSet("Users", "Computers", "Groups", "ForestInfo", "Sites", "Trusts", "Policies", "OrganizationalUnits", "DomainInfo", "DomainControllers")]
        [string]$ObjectType,

        [Parameter()]
        [string]$Filter = "*", # Default filter

        [Parameter()]
        [string[]]$Properties, # Properties to retrieve

        [Parameter()]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory)]
        [scriptblock]$ProcessingScript, # Transformation logic for each object

        [string]$ActivityName = "Retrieving $ObjectType"
    )

    try {
        Write-Log "Starting retrieval of $ObjectType..." -Level Info

        # Map ObjectType to corresponding AD cmdlet
        $cmdletName = switch ($ObjectType) {
            "Users" { "Get-ADUser" }
            "Computers" { "Get-ADComputer" }
            "Groups" { "Get-ADGroup" }
            "ForestInfo" { "Get-ADForest" }
            "Sites" { "Get-ADReplicationSite" }
            "Trusts" { "Get-ADTrust" }
            "Policies" { "Get-GPO" }
            "OrganizationalUnits" { "Get-ADOrganizationalUnit" }
            "DomainInfo" { "Get-ADDomain" }
            "DomainControllers" { "Get-ADDomainController" }
            default { throw "Unsupported ObjectType: $ObjectType" }
        }

        # Count total objects for progress calculation
        Write-Log "Counting total $ObjectType for progress calculation..." -Level Info
        $countParams = @{ Filter = $Filter }
        if ($Credential) { $countParams.Credential = $Credential }

        # Handle single-object cmdlets like Get-ADForest, Get-GPO, Get-ADDomain
        if ($ObjectType -in @("ForestInfo", "Policies", "DomainInfo")) {
            $total = 1
        }
        else {
            $total = (& $cmdletName @countParams | Measure-Object).Count
        }

        if ($total -eq 0) {
            Write-Log "No $ObjectType found based on the specified criteria." -Level Warning
            return $null
        }

        Write-Log "Retrieving and processing $total $ObjectType..." -Level Info

        # Build retrieval parameters
        $getParams = @{ Filter = $Filter }
        if ($Properties) { $getParams.Properties = $Properties }
        if ($Credential) { $getParams.Credential = $Credential }

        $count = 0
        $results = (& $cmdletName @getParams) |
        ForEach-Object -Begin {
            Show-Progress -Activity $ActivityName -Status "Starting..." -PercentComplete 0
        } -Process {
            $count++
            try {
                # Apply the transformation logic provided by the caller
                $obj = & $ProcessingScript $_

                # Update progress
                $percent = [int]( ($count / $total) * 100 )
                Show-Progress -Activity $ActivityName -Status "Processing $ObjectType $count of $total" -PercentComplete $percent

                # Output the transformed object
                $obj
            }
            catch {
                Write-Log "Error processing $ObjectType $($ObjectType -eq 'Users' ? $_.SamAccountName : $_.Name): $($_.Exception.Message)" -Level Warning

                # Create a fallback object in case of processing error
                switch ($ObjectType) {
                    "Users" {
                        $errorObject = [PSCustomObject]@{
                            SamAccountName       = $_.SamAccountName
                            DisplayName          = $null
                            EmailAddress         = $null
                            Enabled              = $null
                            LastLogonDate        = $null
                            PasswordLastSet      = $null
                            PasswordNeverExpires = $null
                            PasswordExpired      = $null
                            DistinguishedName    = $_.DistinguishedName
                            MemberOf             = @()
                            AccountStatus        = "Error"
                            AccessStatus         = "Access Error: $($_.Exception.Message)"
                        }
                        Add-Member -InputObject $errorObject -MemberType ScriptMethod -Name "ToString" -Value {
                            "SamAccountName=$($this.SamAccountName); Status=Error; Groups=0"
                        } -Force
                        $errorObject
                    }
                    "Computers" {
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
                    "Groups" {
                        $errorObject = [PSCustomObject]@{
                            Name                   = $_.Name
                            Description            = $_.Description
                            GroupCategory          = $_.GroupCategory
                            GroupScope             = $_.GroupScope
                            TotalNestedMemberCount = 0
                            Members                = @()
                            Created                = $_.Created
                            Modified               = $_.Modified
                            DistinguishedName      = $_.DistinguishedName
                            AccessStatus           = "Access Error: $($_.Exception.Message)"
                        }
                        Add-Member -InputObject $errorObject -MemberType ScriptMethod -Name "ToString" -Value {
                            "Name=$($this.Name); Status=Error"
                        } -Force
                        $errorObject
                    }
                    "ForestInfo" {
                        Write-Log "Error retrieving Forest Info: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    "Sites" {
                        Write-Log "Error retrieving Site Info: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    "Trusts" {
                        Write-Log "Error retrieving Trust Info: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    "Policies" {
                        Write-Log "Error retrieving GPOs: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    "OrganizationalUnits" {
                        Write-Log "Error retrieving Organizational Units: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    "DomainInfo" {
                        Write-Log "Error retrieving Domain Info: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    "DomainControllers" {
                        Write-Log "Error retrieving Domain Controllers: $($_.Exception.Message)" -Level Warning
                        return $null
                    }
                    default {
                        Write-Log "Unhandled ObjectType: $ObjectType" -Level Warning
                        return $null
                    }
                }
            }
        } -End {
            Show-Progress -Activity $ActivityName -Completed
        }

        Write-Log "Successfully retrieved $($results.Count) $ObjectType." -Level Info
        return $results
    }
    catch {
        Write-Log "Failed to retrieve ${ObjectType}: $($_.Exception.Message)" -Level Error
    }
}

#endregion