function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath,
        [string]$DomainController = $env:LOGONSERVER.TrimStart("\\")  # Get current logged-on DC
    )
    
    try {
        Write-Log "Retrieving groups and members from $DomainController..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        # Get the current user's domain
        $currentDomain = $env:USERDOMAIN
        Write-Log "Current domain: $currentDomain" -Level Info
        
        # Parameters for AD cmdlets
        $adParams = @{
            Server      = $DomainController
            ErrorAction = 'Stop'
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "Getting groups..."
        
        # Get groups with basic properties first
        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup @adParams -Filter * -Properties Description, Created, Modified, DistinguishedName
        }
        
        $groupObjects = @()
        $totalGroups = ($groups | Measure-Object).Count
        $currentGroup = 0
        
        foreach ($group in $groups) {
            $currentGroup++
            $percentComplete = ($currentGroup / $totalGroups) * 100
            
            Show-ProgressHelper -Activity "AD Inventory" `
                -Status "Processing group $currentGroup of $totalGroups" `
                -CurrentOperation $group.Name `
                -PercentComplete $percentComplete
            
            try {
                # Get members with timeout protection
                $members = @()
                $memberCount = 0
                
                # Use a timeout mechanism for member retrieval
                $memberJob = Start-Job -ScriptBlock {
                    param($groupDN, $server)
                    Get-ADGroup -Identity $groupDN -Properties Members -Server $server |
                    Select-Object -ExpandProperty Members
                } -ArgumentList $group.DistinguishedName, $DomainController
                
                # Wait up to 30 seconds for member retrieval
                if (Wait-Job $memberJob -Timeout 30) {
                    $memberDNs = Receive-Job $memberJob
                    $memberCount = ($memberDNs | Measure-Object).Count
                    
                    # Only process first 100 members for large groups
                    if ($memberCount -gt 100) {
                        $memberDNs = $memberDNs | Select-Object -First 100
                        Write-Log "Group $($group.Name) has more than 100 members. Only processing first 100." -Level Warning
                    }
                    
                    foreach ($memberDN in $memberDNs) {
                        try {
                            $member = Get-ADObject $memberDN -Server $DomainController -Properties name, objectClass -ErrorAction Stop
                            $members += "$($member.objectClass):$($member.name)"
                        }
                        catch {
                            $members += "Inaccessible:$memberDN"
                        }
                    }
                }
                else {
                    Write-Log "Timeout while retrieving members for group $($group.Name)" -Level Warning
                    $members = @("Timeout occurred while retrieving members")
                }
                
                Remove-Job $memberJob -Force
                
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                $members = @("Error retrieving members")
            }
            
            # Extract OU path
            $ouPath = ($group.DistinguishedName -split ',(?=OU=)' | Where-Object { $_ -match '^OU=' }) -join ','
            if (-not $ouPath) { $ouPath = "No OU (Root)" }
            
            $groupObjects += [PSCustomObject]@{
                Name              = $group.Name
                Description       = $group.Description
                MemberCount       = $memberCount
                Members           = ($members | Select-Object -First 100) -join "; "
                Created           = $group.Created
                Modified          = $group.Modified
                DistinguishedName = $group.DistinguishedName
                OUPath            = $ouPath
                AccessStatus      = if ($members -contains "Error retrieving members") { "Partial Access" } else { "Full Access" }
            }
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $groupObjects -ObjectType "Groups"
        Write-Host "`n=== Group Collection Statistics ==="
        Write-Host "Total Groups: $($stats.TotalCount)"
        Write-Host "Accessible Groups: $(($groupObjects | Where-Object { $_.AccessStatus -eq 'Full Access' }).Count)"
        Write-Host "Partially Accessible Groups: $(($groupObjects | Where-Object { $_.AccessStatus -eq 'Partial Access' }).Count)"
        Write-Host "`nDistribution by OU:"
        $stats.OUDistribution.GetEnumerator() | Sort-Object Name | ForEach-Object {
            Write-Host ("{0,-50} : {1,5}" -f $_.Key, $_.Value)
        }
        
        if ($Export) {
            Show-ProgressHelper -Activity "AD Inventory" -Status "Exporting group data..."
            if (-not (Test-Path $ExportPath)) {
                New-Item -ItemType Directory -Path $ExportPath -Force
            }
            $exportFile = Join-Path $ExportPath "Groups_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $groupObjects | Export-Csv $exportFile -NoTypeInformation
            Write-Log "Groups exported to $exportFile" -Level Info
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "Group retrieval complete" -Completed
        return $groupObjects
        
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve groups or group members. Check permissions."
    }
}