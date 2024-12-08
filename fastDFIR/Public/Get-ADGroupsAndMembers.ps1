function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving groups and members..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "Getting groups..."
        
        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties Members, Description, Info, Created, Modified -ErrorAction Stop
        }
        
        $groupObjects = Get-ADObjects -ObjectType "Groups" -Objects $groups -ProcessingScript {
            param($group)
            
            $members = $null
            if ($group.Members) {
                $memberNames = foreach ($memberDN in $group.Members) {
                    try {
                        $member = Invoke-WithRetry -ScriptBlock {
                            Get-ADObject $memberDN -Properties name -ErrorAction Stop
                        }
                        $member.Name
                    }
                    catch {
                        Write-Log "Could not resolve member $memberDN" -Level Warning
                        "Unknown Member"
                    }
                }
                $members = $memberNames -join "; "
            }
            
            [PSCustomObject]@{
                Name              = $group.Name
                Description       = $group.Description
                MemberCount       = ($group.Members | Measure-Object).Count
                Members           = $members
                Created           = $group.Created
                Modified          = $group.Modified
                DistinguishedName = $group.DistinguishedName
            }
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
