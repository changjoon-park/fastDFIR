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
                $groupObject = [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory
                    GroupScope             = $group.GroupScope
                    TotalNestedMemberCount = $group.Members.Count
                    Members                = $group.Members
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Success"
                }

                Add-Member -InputObject $groupObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); Category=$($this.GroupCategory); Scope=$($this.GroupScope); Members=$($this.TotalNestedMemberCount)"
                }

                $groupObject
            }
            catch {
                Write-Log "Error processing group $($group.Name): $($_.Exception.Message)" -Level Warning
                
                $groupObject = [PSCustomObject]@{
                    Name                   = $group.Name
                    Description            = $group.Description
                    GroupCategory          = $group.GroupCategory
                    GroupScope             = $group.GroupScope
                    TotalNestedMemberCount = 0
                    Members                = @()
                    Created                = $group.Created
                    Modified               = $group.Modified
                    DistinguishedName      = $group.DistinguishedName
                    AccessStatus           = "Access Error: $($_.Exception.Message)"
                }

                Add-Member -InputObject $groupObject -MemberType ScriptMethod -Name "ToString" -Value {
                    "Name=$($this.Name); Status=Error"
                }

                $groupObject
            }
        }

        return $groupObjects
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Unable to retrieve groups. Check permissions."
    }
}
