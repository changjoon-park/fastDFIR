function Get-DomainReport {
    [CmdletBinding()]
    param(
        [ValidateScript({ Test-Path $_ })]
        [string]$ExportPath = $script:Config.ExportPath
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

        # Sequential collection
        foreach ($component in $components.Keys) {
            $componentSw = [System.Diagnostics.Stopwatch]::StartNew()
            try {
                Write-Log "Collecting $component..." -Level Info
                $results[$component] = & $components[$component]
                $componentTiming[$component] = Convert-MillisecondsToReadable -Milliseconds $componentSw.ElapsedMilliseconds
            }
            catch {
                $errors[$component] = $_.Exception.Message
                $componentTiming[$component] = Convert-MillisecondsToReadable -Milliseconds $componentSw.ElapsedMilliseconds
                Write-Log "Error collecting ${component}: $($_.Exception.Message)" -Level Error
                if (-not $ContinueOnError) { throw }
            }
        }

        # Create the final report object
        $domainReport = [PSCustomObject]@{
            CollectionTime     = Get-Date
            CollectionStatus   = if ($errors.Count -eq 0) { "Complete" } else { "Partial" }
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

# Main method addition function
function Add-DomainReportMethods {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$DomainReport
    )
    
    # Add ToString methods
    Add-ToStringMethods -DomainReport $DomainReport
    
    # Add Search methods
    Add-SearchMethods -DomainReport $DomainReport
    
    # Add Network methods
    Add-NetworkMethods -DomainReport $DomainReport
    
    # Add Security methods
    Add-SecurityMethods -DomainReport $DomainReport
}

# Individual method groups
function Add-ToStringMethods {
    param ($DomainReport)
    
    $basicInfoToString = {
        $forest = if ($this.ForestInfo.Name) { $this.ForestInfo.Name } else { "N/A" }
        $domain = if ($this.DomainInfo.DomainName) { $this.DomainInfo.DomainName } else { "N/A" }
        $sites = if ($this.Sites.TotalSites) { $this.Sites.TotalSites } else { "0" }
        $trusts = if ($this.TrustInfo) { $this.TrustInfo.Count } else { "0" }
        
        return "forest=$forest, domain=$domain, sites=$sites, trusts=$trusts"
    }

    $domainObjectsToString = {
        $users = if ($this.Users) { $this.Users.Count } else { "0" }
        $computers = if ($this.Computers) { $this.Computers.Count } else { "0" }
        $groups = if ($this.Groups) { $this.Groups.Count } else { "0" }
        
        return "users=$users, computers=$computers, groups=$groups"
    }

    $securitySettingsToString = {
        $spns = if ($this.SecurityConfig.SPNConfiguration) { $this.SecurityConfig.SPNConfiguration.Count } else { "0" }
        $acls = if ($this.SecurityConfig.ObjectACLs) { $this.SecurityConfig.ObjectACLs.Count } else { "0" }
        return "SPNs=$spns, ACLs=$acls"
    }

    Add-Member -InputObject $DomainReport.BasicInfo -MemberType ScriptMethod -Name "ToString" -Value $basicInfoToString -Force
    Add-Member -InputObject $DomainReport.DomainObjects -MemberType ScriptMethod -Name "ToString" -Value $domainObjectsToString -Force
    Add-Member -InputObject $DomainReport.SecuritySettings -MemberType ScriptMethod -Name "ToString" -Value $securitySettingsToString -Force
}

function Add-SearchMethods {
    param ($DomainReport)
    
    $searchUsers = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Users) {
            Write-Log "No user data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Users | Where-Object {
            $_.SamAccountName -like "*$SearchTerm*" -or
            $_.DisplayName -like "*$SearchTerm*" -or
            $_.EmailAddress -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No users found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    $searchComputers = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computer data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Computers | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.IPv4Address -like "*$SearchTerm*" -or
            $_.DNSHostName -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No computers found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchUsers" -Value $searchUsers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchComputers" -Value $searchComputers -Force
}

function Add-NetworkMethods {
    param ($DomainReport)
    
    $networkMethods = @{
        TestTargetConnection = Get-TestTargetConnectionMethod
        TestConnections      = Get-TestConnectionsMethod
        ScanCommonPorts      = Get-ScanCommonPortsMethod
        ScanTargetPorts      = Get-ScanTargetPortsMethod
    }

    foreach ($method in $networkMethods.GetEnumerator()) {
        Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name $method.Key -Value $method.Value -Force
    }
}

function Add-SecurityMethods {
    param ($DomainReport)
    
    $securityMethods = @{
        FindSuspiciousSPNs    = Get-FindSuspiciousSPNsMethod
        DisplaySuspiciousSPNs = Get-DisplaySuspiciousSPNsMethod
    }

    foreach ($method in $securityMethods.GetEnumerator()) {
        Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name $method.Key -Value $method.Value -Force
    }
}

# Helper functions for network methods
function Get-TestTargetConnectionMethod {
    return {
        param(
            [Parameter(Mandatory = $true)]
            $ADComputer
        )

        $target = if ($ADComputer.DNSHostName) { $ADComputer.DNSHostName } else { $ADComputer.Name }

        if ([string]::IsNullOrEmpty($target)) {
            Write-Log "Invalid target. The specified ADComputer has no resolvable DNSHostName or Name." -Level Warning
            return $null
        }

        $reachable = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue

        $ADComputer.IsAlive = $reachable
        $ADComputer.NetworkStatus = if ($reachable) { "Online" } else { "Offline/Unreachable" }

        return [PSCustomObject]@{
            Computer      = $target
            IsAlive       = $ADComputer.IsAlive
            NetworkStatus = $ADComputer.NetworkStatus
        }
    }
}

function Get-TestConnectionsMethod {
    return {
        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computers found in the domain report. Cannot test connections." -Level Warning
            return $null
        }

        $results = @()
        foreach ($comp in $this.DomainObjects.Computers) {
            $target = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }

            if ([string]::IsNullOrEmpty($target)) {
                Write-Log "Skipping $($comp.Name) due to no valid DNSHostName or Name." -Level Warning
                $comp.IsAlive = $false
                $comp.NetworkStatus = "Invalid Target"
                $results += [PSCustomObject]@{
                    Computer      = $comp.Name
                    IsAlive       = $comp.IsAlive
                    NetworkStatus = $comp.NetworkStatus
                }
                continue
            }

            $reachable = Test-Connection -ComputerName $target -Count 1 -Quiet -ErrorAction SilentlyContinue
            
            $comp.IsAlive = $reachable
            $comp.NetworkStatus = if ($reachable) { "Online" } else { "Offline/Unreachable" }

            $results += [PSCustomObject]@{
                Computer      = $target
                IsAlive       = $comp.IsAlive
                NetworkStatus = $comp.NetworkStatus
            }
        }

        if (-not $this.PSObject.Properties.Name.Contains('NetworkConnectivityResults')) {
            Add-Member -InputObject $this -MemberType NoteProperty -Name 'NetworkConnectivityResults' -Value $results
        }
        else {
            $this.NetworkConnectivityResults = $results
        }

        return $results
    }
}

function Get-ScanCommonPortsMethod {
    return {
        param(
            [int[]]$Ports = (80, 443, 445, 3389, 5985),
            [int]$Timeout = 1000
        )

        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computers found in the domain report. Cannot scan ports." -Level Warning
            return $null
        }

        $results = @()
        foreach ($comp in $this.DomainObjects.Computers) {
            if (-not $comp.IsAlive) {
                Write-Log "Skipping $($comp.Name) because IsAlive=$($comp.IsAlive)" -Level Info
                continue
            }

            $target = if ($comp.DNSHostName) { $comp.DNSHostName } else { $comp.Name }

            if ([string]::IsNullOrEmpty($target)) {
                Write-Log "Invalid target for $($comp.Name): No resolvable DNSHostName or Name." -Level Warning
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

        if (-not $this.PSObject.Properties.Name.Contains('NetworkPortScanResults')) {
            Add-Member -InputObject $this -MemberType NoteProperty -Name 'NetworkPortScanResults' -Value $results
        }
        else {
            $this.NetworkPortScanResults = $results
        }

        return $this.NetworkPortScanResults
    }
}

function Get-ScanTargetPortsMethod {
    return {
        param(
            [Parameter(Mandatory = $true)]
            $ADComputer,
            [Parameter(Mandatory = $true)]
            [int[]]$Ports
        )

        if (-not $ADComputer.IsAlive) {
            Write-Log "Skipping $($ADComputer.Name) because IsAlive=$($ADComputer.IsAlive)" -Level Warning
            return $null
        }

        $target = if ($ADComputer.DNSHostName) { $ADComputer.DNSHostName } else { $ADComputer.Name }

        if ([string]::IsNullOrEmpty($target)) {
            Write-Log "Invalid target. The specified ADComputer has no resolvable DNSHostName or Name." -Level Warning
            return $null
        }

        $results = @()
        foreach ($port in $Ports) {
            $tcp = New-Object System.Net.Sockets.TcpClient
            try {
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
}

function Get-FindSuspiciousSPNsMethod {
    return {
        $spnResults = Find-SuspiciousSPNs -Computers $this.DomainObjects.Computers -Users $this.DomainObjects.Users
        
        if (-not $this.SecuritySettings.PSObject.Properties.Name.Contains('SuspiciousSPNs')) {
            Add-Member -InputObject $this.SecuritySettings -MemberType NoteProperty -Name 'SuspiciousSPNs' -Value $spnResults
        }
        else {
            $this.SecuritySettings.SuspiciousSPNs = $spnResults
        }
        
        return $spnResults
    }
}

function Get-DisplaySuspiciousSPNsMethod {
    return {
        if (-not $this.SecuritySettings.PSObject.Properties.Name.Contains('SuspiciousSPNs')) {
            Write-Log "No suspicious SPNs found. Running FindSuspiciousSPNs..." -Level Info
            $this.FindSuspiciousSPNs()
        }
    
        if ($this.SecuritySettings.SuspiciousSPNs) {
            Write-Log "`nSuspicious SPNs Found:" -Level Warning
            $this.SecuritySettings.SuspiciousSPNs | ForEach-Object {
                Write-Log "`nObject: $($_.ObjectName) ($($_.ObjectType))" -Level Warning
                Write-Log "Risk Level: $($_.RiskLevel)" -Level $(if ($_.RiskLevel -eq 'High') { 'Error' } else { 'Warning' })
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
}