function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving groups and members..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        # First get all groups with basic properties in one quick query
        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties Name, Description, Created, Modified, DistinguishedName, 
            memberOf, GroupCategory, GroupScope -ErrorAction Stop
        }
        
        $totalGroups = ($groups | Measure-Object).Count
        Write-Log "Found $totalGroups groups to process" -Level Info
        
        $groupObjects = Get-ADObjects -ObjectType "Groups" -Objects $groups -ProcessingScript {
            param($group)
            
            try {
                # Fast member count retrieval with timeout protection
                $memberCount = 0
                $members = "Not retrieved due to timeout"
                
                $memberJob = Start-Job -ScriptBlock {
                    param($groupDN)
                    (Get-ADGroup $groupDN -Properties Members).Members.Count
                } -ArgumentList $group.DistinguishedName
                
                # Only wait 5 seconds max for member count
                if (Wait-Job $memberJob -Timeout 5) {
                    $memberCount = Receive-Job $memberJob
                }
                Remove-Job $memberJob -Force -ErrorAction SilentlyContinue
                
                [PSCustomObject]@{
                    Name              = $group.Name
                    Description       = $group.Description
                    MemberCount       = $memberCount
                    GroupCategory     = $group.GroupCategory
                    GroupScope        = $group.GroupScope
                    Created           = $group.Created
                    Modified          = $group.Modified
                    DistinguishedName = $group.DistinguishedName
                    AccessStatus      = "Success"
                }
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name              = $group.Name
                    Description       = $group.Description
                    MemberCount       = 0
                    GroupCategory     = $group.GroupCategory
                    GroupScope        = $group.GroupScope
                    Created           = $group.Created
                    Modified          = $group.Modified
                    DistinguishedName = $group.DistinguishedName
                    AccessStatus      = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        # Generate and display statistics using Get-CollectionStatistics
        $stats = Get-CollectionStatistics -Data $groupObjects -ObjectType "Groups" -IncludeAccessStatus
        $stats.DisplayStatistics()
        
        if ($Export) {
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
        Show-ErrorBox "Unable to retrieve groups. Check permissions."
        return $null
    }
}