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
