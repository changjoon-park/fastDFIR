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

        # Determine if the cmdlet supports the -Filter parameter
        $objectTypesWithFilter = @("Users", "Computers", "Groups", "Sites", "Trusts", "OrganizationalUnits", "DomainControllers")
        $supportsFilter = $objectTypesWithFilter -contains $ObjectType

        # Count total objects for progress calculation
        Write-Log "Counting total $ObjectType for progress calculation..." -Level Info
        $countParams = @{}
        if ($supportsFilter) {
            $countParams['Filter'] = $Filter
        }
        if ($Credential) {
            $countParams['Credential'] = $Credential
        }

        # Handle single-object cmdlets like Get-ADForest, Get-GPO, Get-ADDomain
        if ($ObjectType -in @("ForestInfo", "Policies", "DomainInfo")) {
            $total = 1
        }
        else {
            # Attempt to retrieve objects to count them
            try {
                $total = (& $cmdletName @countParams | Measure-Object).Count
            }
            catch {
                Write-Log "Error counting objects for ${ObjectType} $($_.Exception.Message)" -Level Error
                return $null
            }
        }

        if ($total -eq 0) {
            Write-Log "No $ObjectType found based on the specified criteria." -Level Warning
            return $null
        }

        Write-Log "Retrieving and processing $total $ObjectType..." -Level Info

        # Build retrieval parameters
        $getParams = @{}
        if ($supportsFilter) {
            $getParams['Filter'] = $Filter
        }
        if ($Properties) {
            $getParams['Properties'] = $Properties
        }
        if ($Credential) {
            $getParams['Credential'] = $Credential
        }

        $count = 0
        $results = @()
        $cmd = { & $cmdletName @using:getParams }

        $objects = try {
            & $cmd
        }
        catch {
            Write-Log "Error retrieving ${ObjectType} $($_.Exception.Message)" -Level Error
            return $null
        }

        foreach ($item in $objects) {
            $count++
            try {
                # Apply the transformation logic provided by the caller
                $obj = & $ProcessingScript $item

                # Update progress using Show-ProgressHelper
                $percent = [int]( ($count / $total) * 100 )
                Show-ProgressHelper -Activity $ActivityName -Status "Processing $ObjectType $count of $total" -PercentComplete $percent

                # Collect the transformed object
                $results += $obj
            }
            catch {
                Write-Log "Error processing ${ObjectType} $($_.Exception.Message)" -Level Warning

                # Create a fallback object in case of processing error
                switch ($ObjectType) {
                    "Users" {
                        $errorObject = [PSCustomObject]@{
                            SamAccountName       = $item.SamAccountName
                            DisplayName          = $null
                            EmailAddress         = $null
                            Enabled              = $null
                            LastLogonDate        = $null
                            PasswordLastSet      = $null
                            PasswordNeverExpires = $null
                            PasswordExpired      = $null
                            DistinguishedName    = $item.DistinguishedName
                            MemberOf             = @()
                            AccountStatus        = "Error"
                            AccessStatus         = "Access Error: $($_.Exception.Message)"
                        }
                        Add-Member -InputObject $errorObject -MemberType ScriptMethod -Name "ToString" -Value {
                            "SamAccountName=$($this.SamAccountName); Status=Error; Groups=0"
                        } -Force
                        $results += $errorObject
                    }
                    "Computers" {
                        $errorObject = [PSCustomObject]@{
                            Name                   = $item.Name
                            IPv4Address            = $null
                            DNSHostName            = $null
                            OperatingSystem        = $null
                            OperatingSystemVersion = $null
                            Enabled                = $null
                            LastLogonDate          = $null
                            Created                = $null
                            Modified               = $null
                            DistinguishedName      = $item.DistinguishedName
                            ServicePrincipalNames  = $null
                            MemberOf               = @()
                            AccessStatus           = "Access Error: $($_.Exception.Message)"
                            NetworkStatus          = "Error"
                            IsAlive                = $false
                        }
                        Add-Member -InputObject $errorObject -MemberType ScriptMethod -Name "ToString" -Value {
                            "Name=$($this.Name); NetworkStatus=Error; IsAlive=$($this.IsAlive); Groups=0"
                        } -Force
                        $results += $errorObject
                    }
                    "Groups" {
                        $errorObject = [PSCustomObject]@{
                            Name                   = $item.Name
                            Description            = $item.Description
                            GroupCategory          = $item.GroupCategory
                            GroupScope             = $item.GroupScope
                            TotalNestedMemberCount = 0
                            Members                = @()
                            Created                = $item.Created
                            Modified               = $item.Modified
                            DistinguishedName      = $item.DistinguishedName
                            AccessStatus           = "Access Error: $($_.Exception.Message)"
                        }
                        Add-Member -InputObject $errorObject -MemberType ScriptMethod -Name "ToString" -Value {
                            "Name=$($this.Name); Status=Error"
                        } -Force
                        $results += $errorObject
                    }
                    "ForestInfo" {
                        Write-Log "Error retrieving Forest Info: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    "Sites" {
                        Write-Log "Error retrieving Site Info: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    "Trusts" {
                        Write-Log "Error retrieving Trust Info: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    "Policies" {
                        Write-Log "Error retrieving GPOs: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    "OrganizationalUnits" {
                        Write-Log "Error retrieving Organizational Units: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    "DomainInfo" {
                        Write-Log "Error retrieving Domain Info: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    "DomainControllers" {
                        Write-Log "Error retrieving Domain Controllers: $($_.Exception.Message)" -Level Warning
                        $results += $null
                    }
                    default {
                        Write-Log "Unhandled ObjectType: $ObjectType" -Level Warning
                        $results += $null
                    }
                }
            }
        }

        # Finalize progress using Show-ProgressHelper
        Show-ProgressHelper -Activity $ActivityName -Completed

        Write-Log "Successfully retrieved $($results.Count) $ObjectType." -Level Info
        return $results
    }
    catch {
        Write-Log "Failed to retrieve ${ObjectType}: $($_.Exception.Message)" -Level Error
    }
}