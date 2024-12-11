function Get-DomainReport {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$UseParallel
    )

    try {
        # Initialize tracking variables
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $results = @{}
        $errors = @{}
        $componentTiming = @{}

        # Define collection components
        $components = @{
            'ForestInfo'     = { Get-ADForestInfo }
            'TrustInfo'      = { Get-ADTrustInfo }
            'Sites'          = { Get-ADSiteInfo }
            'DomainInfo'     = { Get-ADDomainInfo }
            'Users'          = { Get-ADUsers }
            'Computers'      = { Get-ADComputers }
            'Groups'         = { Get-ADGroupsAndMembers }
            'SecurityConfig' = { Get-ADSecurityConfiguration }
        }

        # Collect data either in parallel or sequentially
        if ($UseParallel) {
            Write-Log "Starting parallel data collection..." -Level Info

            # Instead of converting to string, just store the scriptblock directly:
            $componentScripts = $components.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{
                    Name        = $_.Key
                    ScriptBlock = $_.Value # $_.Value is already a scriptblock
                }
            }

            # Now in the parallel block, just run it directly:
            $parallelResults = $componentScripts | ForEach-Object -ThrottleLimit $script:Config.MaxConcurrentJobs -Parallel {
                $component = $_.Name
                $scriptBlock = $_.ScriptBlock
                $componentSw = [System.Diagnostics.Stopwatch]::StartNew()

                try {
                    $data = & $scriptBlock
                    @{
                        Name          = $component
                        Data          = $data
                        Error         = $null
                        ExecutionTime = $componentSw.ElapsedMilliseconds
                    }
                }
                catch {
                    @{
                        Name          = $component
                        Data          = $null
                        Error         = $_.Exception.Message
                        ExecutionTime = $componentSw.ElapsedMilliseconds
                    }
                }
            }

            # Process parallel results
            foreach ($result in $parallelResults) {
                if ($result.Error) {
                    $errors[$result.Name] = $result.Error
                    Write-Log "Error collecting $($result.Name): $($result.Error)" -Level Error
                    if (-not $ContinueOnError) { throw $result.Error }
                }
                else {
                    $results[$result.Name] = $result.Data
                }
                $componentTiming[$result.Name] = $result.ExecutionTime
            }
        }
        else {
            # Sequential collection
            foreach ($component in $components.Keys) {
                $componentSw = [System.Diagnostics.Stopwatch]::StartNew()
                try {
                    Write-Log "Collecting $component..." -Level Info
                    $results[$component] = & $components[$component]
                    $componentTiming[$component] = $componentSw.ElapsedMilliseconds
                }
                catch {
                    $errors[$component] = $_.Exception.Message
                    $componentTiming[$component] = $componentSw.ElapsedMilliseconds
                    Write-Log "Error collecting ${component}: $($_.Exception.Message)" -Level Error
                    if (-not $ContinueOnError) { throw }
                }
            }
        }

        # Create the final report object
        $domainReport = [PSCustomObject]@{
            CollectionTime     = Get-Date
            CollectionStatus   = if ($errors.Count -eq 0) { "Complete" } else { "Partial" }
            Errors             = $errors
            PerformanceMetrics = $componentTiming
            TotalExecutionTime = $sw.ElapsedMilliseconds
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
                SecurityConfig = $results['SecurityConfig']
            }
        }

        # Add report generation metadata
        Add-Member -InputObject $domainReport -MemberType NoteProperty -Name "ReportGeneration" -Value @{
            GeneratedBy       = $env:USERNAME
            GeneratedOn       = Get-Date
            ComputerName      = $env:COMPUTERNAME
            PowerShellVersion = $PSVersionTable.PSVersion.ToString()
        }

        # Add methods to the report object
        Add-DomainReportMethods -DomainReport $domainReport


        # Export the report if requested
        if ($ExportPath) {
            $exportFile = Join-Path $ExportPath ("DomainReport_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
            $domainReport | ConvertTo-Json -Depth 10 | Out-File $exportFile
            Write-Log "Report exported to: $exportFile" -Level Info
        }

        return $domainReport
    }
    catch {
        Write-Log "Critical error in Get-DomainReport: $($_.Exception.Message)" -Level Error
        throw
    }
    finally {
        $sw.Stop()
        Write-Log "Total execution time: $($sw.ElapsedMilliseconds)ms" -Level Info
    }
}

# Example usage:
# $report = Get-DomainReport -UseParallel 

function Add-DomainReportMethods {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$DomainReport
    )

    # Add custom ToString() method for BasicInfo
    $basicInfoToString = {
        $forest = if ($this.ForestInfo.Name) { $this.ForestInfo.Name } else { "N/A" }
        $domain = if ($this.DomainInfo.DomainName) { $this.DomainInfo.DomainName } else { "N/A" }
        $sites = if ($this.Sites.TotalSites) { $this.Sites.TotalSites } else { "0" }
        $trusts = if ($this.TrustInfo) { $this.TrustInfo.Count } else { "0" }
        
        return "forest=$forest, domain=$domain, sites=$sites, trusts=$trusts"
    }

    # Add custom ToString() method for DomainObjects
    $domainObjectsToString = {
        $users = if ($this.Users) { $this.Users.Count } else { "0" }
        $computers = if ($this.Computers) { $this.Computers.Count } else { "0" }
        $groups = if ($this.Groups) { $this.Groups.Count } else { "0" }
        
        return "users=$users, computers=$computers, groups=$groups"
    }

    # Add custom ToString() method for SecuritySettings
    $securitySettingsToString = {
        $spns = if ($this.SecurityConfig.SPNConfiguration) { 
            $this.SecurityConfig.SPNConfiguration.Count 
        }
        else { 
            "0" 
        }
        
        $acls = if ($this.SecurityConfig.ObjectACLs) { 
            $this.SecurityConfig.ObjectACLs.Count 
        }
        else { 
            "0" 
        }
        
        return "SPNs=$spns, ACLs=$acls"
    }
    # Add the ToString methods to each object
    Add-Member -InputObject $DomainReport.BasicInfo -MemberType ScriptMethod -Name "ToString" -Value $basicInfoToString -Force
    Add-Member -InputObject $DomainReport.DomainObjects -MemberType ScriptMethod -Name "ToString" -Value $domainObjectsToString -Force
    Add-Member -InputObject $DomainReport.SecuritySettings -MemberType ScriptMethod -Name "ToString" -Value $securitySettingsToString -Force

    # Define a scriptblock for scanning common ports on all computers
    $scanPorts = {
        param(
            [int[]]$Ports = (80, 443, 445, 3389, 5985),
            [int]$Timeout = 1000
        )

        # Verify we have DomainObjects.Computers
        if (-not $this.DomainObjects.Computers) {
            Write-Host "No computers found in the domain report. Cannot scan ports."
            return $null
        }

        $results = @()

        foreach ($comp in $this.DomainObjects.Computers) {
            # Check if the host is alive before scanning
            if (-not $comp.IsAlive) {
                Write-Host "Skipping $($comp.Name) because IsAlive=$($comp.IsAlive)"
                continue
            }

            # Determine the target hostname or name
            $target = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }

            if ([string]::IsNullOrEmpty($target)) {
                Write-Host "Invalid target for $($comp.Name): No resolvable DNSHostName or Name."
                continue
            }

            foreach ($port in $Ports) {
                $tcp = New-Object System.Net.Sockets.TcpClient
                try {
                    $asyncResult = $tcp.BeginConnect($target, $port, $null, $null)
                    $wait = $asyncResult.AsyncWaitHandle.WaitOne($Timeout)
                    
                    if ($wait -and $tcp.Connected) {
                        $tcp.EndConnect($asyncResult)
                        $results += [PSCustomObject]@{
                            Computer = $target
                            Port     = $port
                            Status   = "Open"
                        }
                    }
                    else {
                        $results += [PSCustomObject]@{
                            Computer = $target
                            Port     = $port
                            Status   = "Closed/Filtered"
                        }
                    }
                }
                catch {
                    $results += [PSCustomObject]@{
                        Computer = $target
                        Port     = $port
                        Status   = "Error: $($_.Exception.Message)"
                    }
                }
                finally {
                    $tcp.Close()
                }
            }
        }

        # Store results in the domain report
        if (-not $this.PSObject.Properties.Name.Contains('NetworkPortScanResults')) {
            Add-Member -InputObject $this -MemberType NoteProperty -Name 'NetworkPortScanResults' -Value $results
        }
        else {
            $this.NetworkPortScanResults = $results
        }

        return $this.NetworkPortScanResults
    }

    # Define a scriptblock for scanning ports on a single target
    $scanTargetPorts = {
        param(
            [Parameter(Mandatory = $true)]
            $ADComputer,
            [Parameter(Mandatory = $true)]
            [int[]]$Ports
        )

        # Check if the host is alive before scanning
        if (-not $ADComputer.IsAlive) {
            Write-Host "Skipping $($ADComputer.Name) because IsAlive=$($ADComputer.IsAlive)"
            return $null
        }

        # Determine the target hostname or name
        $target = if ($ADComputer.DNSHostName) { $ADComputer.DNSHostName } else { $ADComputer.Name }

        if ([string]::IsNullOrEmpty($target)) {
            Write-Host "Invalid target. The specified ADComputer has no resolvable DNSHostName or Name."
            return $null
        }

        $results = @()

        foreach ($port in $Ports) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
                # Attempt connection with a 1 second timeout
                $asyncResult = $tcp.BeginConnect($target, $port, $null, $null)
                $wait = $asyncResult.AsyncWaitHandle.WaitOne(1000)

                if ($wait -and $tcp.Connected) {
                    $tcp.EndConnect($asyncResult)
                    $results += [PSCustomObject]@{
                        Computer = $target
                        Port     = $port
                        Status   = "Open"
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        Computer = $target
                        Port     = $port
                        Status   = "Closed/Filtered"
                    }
                }
            }
            catch {
                $results += [PSCustomObject]@{
                    Computer = $target
                    Port     = $port
                    Status   = "Error: $($_.Exception.Message)"
                }
            }
            finally {
                $tcp.Close()
            }
        }

        return $results
    }

    # Add method to find suspicious SPNs
    $findSuspiciousSPNs = {
        $spnResults = Find-SuspiciousSPNs -Computers $this.DomainObjects.Computers -Users $this.DomainObjects.Users
        
        if (-not $this.SecuritySettings.PSObject.Properties.Name.Contains('SuspiciousSPNs')) {
            Add-Member -InputObject $this.SecuritySettings -MemberType NoteProperty -Name 'SuspiciousSPNs' -Value $spnResults
        }
        else {
            $this.SecuritySettings.SuspiciousSPNs = $spnResults
        }
        
        return $spnResults
    }

    $displaySuspiciousSPNs = {
        if (-not $this.SecuritySettings.PSObject.Properties.Name.Contains('SuspiciousSPNs')) {
            Write-Log "No suspicious SPNs found. Running FindSuspiciousSPNs..." -Level Info
            $this.FindSuspiciousSPNs()
        }
    
        if ($this.SecuritySettings.SuspiciousSPNs) {
            Write-Log "`nSuspicious SPNs Found:" -Level Warning
            $this.SecuritySettings.SuspiciousSPNs | ForEach-Object {
                Write-Log "`nObject: $($_.ObjectName) ($($_.ObjectType))" -Level Warning
                Write-Log "`nRisk Level: $($_.RiskLevel)" -Level $(if ($_.RiskLevel -eq 'High') { 'Error' } else { 'Warning' })
                $_.SuspiciousSPNs.GetEnumerator() | ForEach-Object {
                    Write-Log "  SPN: $($_.Key)" -Level Warning
                    Write-Log "  Reason: $($_.Value)" -Level Warning
                }
            }
        }
        else {
            Write-Log "`nNo suspicious SPNs found." -Level Info
        }
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "ScanCommonPorts" -Value $scanPorts -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "ScanTargetPorts" -Value $scanTargetPorts -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "FindSuspiciousSPNs" -Value $findSuspiciousSPNs
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "DisplaySuspiciousSPNs" -Value $displaySuspiciousSPNs
}