function Get-ADGroupsAndMembers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Groups",
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving groups and members from AD..." -Level Info

        # Define the filter (all groups)
        $filter = '*'

        # Define the properties to retrieve (adjust as needed)
        $properties = @(
            'Name',
            'Description',
            'GroupCategory',
            'GroupScope',
            'Members',
            'Created',
            'Modified',
            'DistinguishedName'
        )

        # Define the processing script for each group
        $processingScript = {
            param($group)

            $totalNestedMemberCount = if ($group.Members) { $group.Members.Count } else { 0 }

            $groupObject = [PSCustomObject]@{
                Name                   = $group.Name
                Description            = $group.Description
                GroupCategory          = $group.GroupCategory
                GroupScope             = $group.GroupScope
                TotalNestedMemberCount = $totalNestedMemberCount
                Members                = $group.Members
                Created                = $group.Created
                Modified               = $group.Modified
                DistinguishedName      = $group.DistinguishedName
                AccessStatus           = "Success"
            }

            # Add a ToString method for better readability
            Add-Member -InputObject $groupObject -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); Category=$($this.GroupCategory); Scope=$($this.GroupScope); Members=$($this.TotalNestedMemberCount)"
            } -Force

            $groupObject
        }

        # Invoke the helper function
        return Invoke-ADRetrievalWithProgress -ObjectType $ObjectType `
            -Filter $filter `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Groups"
    }
    catch {
        Write-Log "Error retrieving groups: $($_.Exception.Message)" -Level Error
    }
}