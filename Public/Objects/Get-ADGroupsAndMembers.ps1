function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Groups",
        [string]$ExportPath = $script:Config.ExportPath
    )
    
    try {
        Write-Log "Retrieving groups and members..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing group retrieval..."
        
        $properties = @(
            'Name',
            'Description',
            'GroupCategory',
            'GroupScope',
            'Members',
            'MemberOf',
            'AdminCount',
            'DistinguishedName',
            'Created',
            'Modified'
        )

        $groups = Invoke-WithRetry -ScriptBlock {
            Get-ADGroup -Filter * -Properties $properties -ErrorAction Stop
        }
        
        $groupObjects = Get-ADObjects -ObjectType $ObjectType -Objects $groups -ProcessingScript {
            param($group)
            
            try {
                # Get nested group membership recursively
                $allMembers = Get-ADGroupNestedMembers -Group $group
                
                # Determine if this is a privileged group
                $isPrivileged = $group.AdminCount -eq 1 -or 
                $group.Name -in @('Domain Admins', 'Enterprise Admins', 'Schema Admins')

                [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory  # Security or Distribution
                    GroupScope             = $group.GroupScope       # Universal, Global, DomainLocal
                    IsPrivileged           = $isPrivileged
                    DirectMemberCount      = ($group.Members | Measure-Object).Count
                    TotalNestedMemberCount = ($allMembers | Measure-Object).Count
                    Members                = $allMembers | ForEach-Object {
                        [PSCustomObject]@{
                            Name              = $_.Name
                            ObjectClass       = $_.ObjectClass
                            DistinguishedName = $_.DistinguishedName
                            MemberType        = if ($_.ObjectClass -eq 'group') { 'NestedGroup' } else { 'DirectMember' }
                        }
                    }
                    ParentGroups           = $group.MemberOf | ForEach-Object {
                        Get-ADGroup $_ | Select-Object -ExpandProperty Name
                    }
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Success"
                }
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                
                [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory
                    GroupScope             = $group.GroupScope
                    IsPrivileged           = $false
                    DirectMemberCount      = 0
                    TotalNestedMemberCount = 0
                    Members                = @()
                    ParentGroups           = @()
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }
            }
        }
        
        return $groupObjects
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve groups. Check permissions."
    }
}

# Helper function to get nested group members recursively
function Get-ADGroupNestedMembers {
    param(
        [Parameter(Mandatory)]
        [Microsoft.ActiveDirectory.Management.ADGroup]$Group,
        [System.Collections.ArrayList]$ProcessedGroups = @()
    )
    
    if ($ProcessedGroups -contains $Group.DistinguishedName) {
        return @()
    }
    
    [void]$ProcessedGroups.Add($Group.DistinguishedName)
    
    $members = foreach ($member in $Group.Members) {
        $obj = Get-ADObject $member -Properties objectClass, name, distinguishedName
        
        if ($obj.objectClass -eq 'group') {
            $obj
            Get-ADGroupNestedMembers -Group (Get-ADGroup $obj -Properties Members) -ProcessedGroups $ProcessedGroups
        }
        else {
            $obj
        }
    }
    
    return $members
}