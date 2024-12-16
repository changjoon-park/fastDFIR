function Find-SuspiciousGroupMemberships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Groups,

        [Parameter(Mandatory)]
        [object[]]$Users,

        # ApprovedMembers hash for certain groups; if not present, no member is implicitly approved.
        [hashtable]$ApprovedMembers = @{
            "Domain Admins"     = @("Administrator")
            "Enterprise Admins" = @("Administrator")
            "Schema Admins"     = @("Administrator")
        },

        [int]$NewAccountThresholdDays = 30
    )

    # Pre-build a lookup for users by their DistinguishedName for faster lookups
    $userByDN = @{}
    foreach ($u in $Users) {
        if ($u.DistinguishedName) {
            $userByDN[$u.DistinguishedName] = $u
        }
    }

    $suspiciousFindings = @()
    
    # Define privileged groups and their constraints
    $privilegedGroups = @{
        "Domain Admins"     = @{
            MaxMembers = 5
            RiskLevel  = "Critical"
        }
        "Enterprise Admins" = @{
            MaxMembers = 3
            RiskLevel  = "Critical"
        }
        "Schema Admins"     = @{
            MaxMembers = 2
            RiskLevel  = "Critical"
        }
        "Backup Operators"  = @{
            MaxMembers = 5
            RiskLevel  = "High"
        }
    }

    foreach ($group in $Groups) {
        if ($privilegedGroups.ContainsKey($group.Name)) {
            $groupConfig = $privilegedGroups[$group.Name]

            # Get the approved list for this group if defined, else empty
            $approvedList = $ApprovedMembers[$group.Name]
            if (-not $approvedList) { $approvedList = @() }

            # Check if the group exceeds the maximum expected membership
            if ($group.Members.Count -gt $groupConfig.MaxMembers) {
                $suspiciousFindings += [PSCustomObject]@{
                    GroupName    = $group.Name
                    Finding      = "Excessive Members"
                    Details      = "Group has $($group.Members.Count) members, expected max $($groupConfig.MaxMembers)"
                    RiskLevel    = $groupConfig.RiskLevel
                    TimeDetected = Get-Date
                }
            }

            # Check each member in the group
            foreach ($memberDN in $group.Members) {
                # Attempt to retrieve the member from the lookup
                $member = $userByDN[$memberDN]
                if ($member) {
                    # If the member is not on the approved list, consider it suspicious
                    if (-not ($approvedList -contains $member.SamAccountName)) {
                        $finding = [PSCustomObject]@{
                            GroupName    = $group.Name
                            MemberName   = $member.SamAccountName
                            Finding      = "Unauthorized Member"
                            Details      = "Member not in approved list"
                            RiskLevel    = $groupConfig.RiskLevel
                            TimeDetected = Get-Date
                        }
                        
                        # If the account was recently created, escalate severity
                        if ($member.Created -gt (Get-Date).AddDays(-$NewAccountThresholdDays)) {
                            $finding.Finding = "Recently Created Account in Privileged Group"
                            $finding.RiskLevel = "Critical"
                        }

                        # If the account is disabled, flag this
                        if ($member.Enabled -eq $false) {
                            $finding.Finding = "Disabled Account in Privileged Group"
                        }
                        
                        $suspiciousFindings += $finding
                    }
                }
                else {
                    # Could not find the user in the provided list - this might also be suspicious,
                    # or could indicate the user data is incomplete. Consider logging a warning.
                }
            }
        }
    }

    return $suspiciousFindings
}