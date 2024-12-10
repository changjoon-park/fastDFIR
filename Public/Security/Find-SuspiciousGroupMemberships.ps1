function Find-SuspiciousGroupMemberships {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Groups,
        [object[]]$Users,
        [hashtable]$ApprovedMembers = @{
            "Domain Admins"     = @("Administrator")
            "Enterprise Admins" = @("Administrator")
            "Schema Admins"     = @("Administrator")
        },
        [int]$NewAccountThresholdDays = 30
    )

    $suspiciousFindings = @()
    
    # Get all privileged groups and their known patterns
    $privilegedGroups = @{
        "Domain Admins"     = @{
            MaxMembers     = 5
            RequiredNaming = "admin"
            RiskLevel      = "Critical"
        }
        "Enterprise Admins" = @{
            MaxMembers     = 3
            RequiredNaming = "admin"
            RiskLevel      = "Critical"
        }
        "Schema Admins"     = @{
            MaxMembers     = 2
            RequiredNaming = "admin"
            RiskLevel      = "Critical"
        }
        "Backup Operators"  = @{
            MaxMembers = 5
            RiskLevel  = "High"
        }
    }

    foreach ($group in $Groups) {
        if ($privilegedGroups.ContainsKey($group.Name)) {
            $groupConfig = $privilegedGroups[$group.Name]
            $approvedList = $ApprovedMembers[$group.Name]
            
            # Check total member count
            if ($group.Members.Count -gt $groupConfig.MaxMembers) {
                $suspiciousFindings += [PSCustomObject]@{
                    GroupName    = $group.Name
                    Finding      = "Excessive Members"
                    Details      = "Group has $($group.Members.Count) members, expected max $($groupConfig.MaxMembers)"
                    RiskLevel    = $groupConfig.RiskLevel
                    TimeDetected = Get-Date
                }
            }

            foreach ($memberDN in $group.Members) {
                $member = $Users | Where-Object { $_.DistinguishedName -eq $memberDN }
                if ($member) {
                    # Check if member is approved
                    if (-not ($approvedList -contains $member.SamAccountName)) {
                        $finding = [PSCustomObject]@{
                            GroupName    = $group.Name
                            MemberName   = $member.SamAccountName
                            Finding      = "Unauthorized Member"
                            Details      = "Member not in approved list"
                            RiskLevel    = $groupConfig.RiskLevel
                            TimeDetected = Get-Date
                        }
                        
                        # Additional checks for suspicious patterns
                        if ($member.Created -gt (Get-Date).AddDays(-$NewAccountThresholdDays)) {
                            $finding.Finding = "Recently Created Account in Privileged Group"
                            $finding.RiskLevel = "Critical"
                        }
                        
                        if ($member.Enabled -eq $false) {
                            $finding.Finding = "Disabled Account in Privileged Group"
                        }
                        
                        $suspiciousFindings += $finding
                    }
                }
            }
        }
    }

    return $suspiciousFindings
}