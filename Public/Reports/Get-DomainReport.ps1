function Get-DomainReport {
    [CmdletBinding(DefaultParameterSetName = 'Collect')]
    param(
        [Parameter(ParameterSetName = 'Collect')]
        [switch]$Export,
        
        [Parameter(ParameterSetName = 'Import', Mandatory = $true)]
        [string]$ImportPath
    )

    # If importing from file - unchanged logic
    if ($PSCmdlet.ParameterSetName -eq 'Import') {
        try {
            Write-Log "Importing domain report from $ImportPath..." -Level Info
            
            if (-not (Test-Path $ImportPath)) {
                throw "Import file not found: $ImportPath"
            }

            # Read and convert JSON content
            $importedContent = Get-Content -Path $ImportPath -Raw | ConvertFrom-Json

            # Create a new PSCustomObject with the imported data
            $domainReport = [PSCustomObject]@{
                CollectionTime     = [DateTime]::Parse($importedContent.CollectionTime)
                CollectionStatus   = $importedContent.CollectionStatus
                CollectionRights   = $importedContent.CollectionRights
                Errors             = $importedContent.Errors
                PerformanceMetrics = $importedContent.PerformanceMetrics
                TotalExecutionTime = $importedContent.TotalExecutionTime
                BasicInfo          = $importedContent.BasicInfo
                DomainObjects      = $importedContent.DomainObjects
                SecuritySettings   = $importedContent.SecuritySettings
                ReportGeneration   = $importedContent.ReportGeneration
            }

            # Add methods back to the imported object
            Add-DomainReportMethods -DomainReport $domainReport

            Write-Log "Successfully imported domain report from $ImportPath" -Level Info
            return $domainReport
        }
        catch {
            Write-Log "Error importing domain report: $($_.Exception.Message)" -Level Error
            throw
        }
    }

    # COLLECTION LOGIC
    try {
        Write-Log "Verifying domain membership..." -Level Info
        # Check if the computer is domain-joined
        try {
            $null = Get-ADDomain -ErrorAction Stop
        }
        catch {
            Write-Log "This computer does not appear to be joined to a domain or cannot access AD." -Level Error
            return
        }

        # Check current user admin rights
        Write-Log "Checking administrative rights..." -Level Info
        $currentUser = $env:USERNAME
        $adminRights = Test-AdminRights -Username $currentUser

        # If not AD Admin, prompt for credentials to re-check
        $adminCreds = $null
        if (-not $adminRights.IsADAdmin) {
            Write-Log "Current user is not an AD Admin. Prompting for alternate credentials..." -Level Warning
            $adminCreds = Get-Credential -Message "Enter credentials for an AD Admin user"
            
            # Re-check admin rights using the supplied credentials
            $adminRights = Test-AdminRights -Username $adminCreds.UserName -Credential $adminCreds

            # If still not AD admin and not OU admin, no further data collection
            if ((-not $adminRights.IsADAdmin) -and (-not $adminRights.IsOUAdmin)) {
                Write-Log "User does not have AD Admin or OU Admin rights. No data will be collected." -Level Warning
                return
            }
        }

        # Prepare the list of functions to call based on admin rights
        $componentFunctions = @{}

        # Always get DomainInfo
        $componentFunctions['DomainInfo'] = {
            if ($adminCreds) {
                Get-ADDomainInfo -Credential $adminCreds
            }
            else {
                Get-ADDomainInfo
            }
        }

        if ($adminRights.IsADAdmin) {
            Write-Log "AD Admin rights confirmed - collecting all data" -Level Info
            # Full access components
            $componentFunctions += @{
                'ForestInfo'     = { if ($adminCreds) { Get-ADForestInfo -Credential $adminCreds } else { Get-ADForestInfo } }
                'TrustInfo'      = { if ($adminCreds) { Get-ADTrustInfo -Credential $adminCreds } else { Get-ADTrustInfo } }
                'Sites'          = { if ($adminCreds) { Get-ADSiteInfo -Credential $adminCreds } else { Get-ADSiteInfo } }
                'Users'          = { if ($adminCreds) { Get-ADUsers -IncludeDisabled -Credential $adminCreds } else { Get-ADUsers -IncludeDisabled } }
                'Computers'      = { if ($adminCreds) { Get-ADComputers -Credential $adminCreds } else { Get-ADComputers } }
                'Groups'         = { if ($adminCreds) { Get-ADGroupsAndMembers -Credential $adminCreds } else { Get-ADGroupsAndMembers } }
                'PolicyInfo'     = { if ($adminCreds) { Get-ADPolicyInfo -Credential $adminCreds } else { Get-ADPolicyInfo } }
                'SecurityConfig' = { if ($adminCreds) { Get-ADSecurityConfiguration -Credential $adminCreds } else { Get-ADSecurityConfiguration } }
            }
        }
        elseif ($adminRights.IsOUAdmin) {
            Write-Log "OU Admin rights detected - collecting limited data" -Level Info
            # Limited access components
            $componentFunctions += @{
                'Users'     = { if ($adminCreds) { Get-ADUsers -IncludeDisabled -Credential $adminCreds } else { Get-ADUsers -IncludeDisabled } }
                'Computers' = { if ($adminCreds) { Get-ADComputers -Credential $adminCreds } else { Get-ADComputers } }
                'Groups'    = { if ($adminCreds) { Get-ADGroupsAndMembers -Credential $adminCreds } else { Get-ADGroupsAndMembers } }
            }
        }

        # Initialize stopwatch for total execution time
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @{}
        $errors = @{}
        $componentTiming = @{}

        # Collect data sequentially
        foreach ($component in $componentFunctions.Keys) {
            $componentSw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                Write-Log "Collecting $component..." -Level Info
                $results[$component] = & $componentFunctions[$component]
                $componentTiming[$component] = Convert-MillisecondsToReadable -Milliseconds $componentSw.ElapsedMilliseconds
            }
            catch {
                $errors[$component] = $_.Exception.Message
                $componentTiming[$component] = Convert-MillisecondsToReadable -Milliseconds $componentSw.ElapsedMilliseconds
                Write-Log "Error collecting ${component}: $($_.Exception.Message)" -Level Error
                # Decide whether to continue on error or throw
                # For example, to continue:
                continue
            }
        }

        # Stop the stopwatch
        $sw.Stop()

        # Create the final report object
        $domainReport = [PSCustomObject]@{
            CollectionTime     = Get-Date
            CollectionStatus   = if ($errors.Count -eq 0) { "Complete" } else { "Partial" }
            CollectionRights   = $adminRights
            Errors             = $errors
            PerformanceMetrics = $componentTiming
            TotalExecutionTime = Convert-MillisecondsToReadable -Milliseconds $sw.ElapsedMilliseconds
            BasicInfo          = [PSCustomObject]@{
                ForestInfo = $results['ForestInfo']
                TrustInfo  = $results['TrustInfo']
                Sites      = $results['Sites']
                DomainInfo = $results['DomainInfo']
            }
            DomainObjects      = [PSCustomObject]@{
                Users     = $results['Users']
                Computers = $results['Computers']
                Groups    = $results['Groups']
            }
            SecuritySettings   = [PSCustomObject]@{
                PolicyInfo     = $results['PolicyInfo']
                SecurityConfig = $results['SecurityConfig']
            }
        }

        # Add report generation metadata
        Add-Member -InputObject $domainReport -MemberType NoteProperty -Name "ReportGeneration" -Value @{
            GeneratedBy       = $currentUser
            GeneratedOn       = Get-Date
            ComputerName      = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
            UserRights        = $adminRights
        }

        # Add methods to the report object
        Add-DomainReportMethods -DomainReport $domainReport

        # Export if switch is set
        if ($Export) {
            $domainReport.Export()  # Use the Export method with default path
        }

        return $domainReport
    }
    catch {
        Write-Log "Critical error in Get-DomainReport: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        Write-Log "Total execution time: $($sw.ElapsedMilliseconds)ms" -Level Info
    }
}