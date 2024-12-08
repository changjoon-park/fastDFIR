function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Groups",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving groups and members..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        # Retrieve all groups and their members in one go
        # Include the 'Members' property so we can count directly without extra queries

        $properties = @(
            'Name',
            'Description',
            'Created',
            'Modified',
            'memberOf',
            'GroupCategory',
            'GroupScope',
            'Members',
            'DistinguishedName'
        )

        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $totalGroups = ($groups | Measure-Object).Count
        Write-Log "Found $totalGroups groups to process" -Level Info
        
        $groupObjects = Get-ADObjects -ObjectType $ObjectType -Objects $groups -ProcessingScript {
            param($group)
            
            try {
                # Since we already have the Members property, just count it
                $memberCount = if ($group.Members) { $group.Members.Count } else { 0 }
                
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
        $stats = Get-CollectionStatistics -Data $groupObjects -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()

        # Export data 
        Export-ADData -ObjectType $ObjectType -Data $groupObjects -ExportPath $ExportPath
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "Group retrieval complete" -Completed
        return $groupObjects
        
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve groups. Check permissions."
        return $null
    }
}