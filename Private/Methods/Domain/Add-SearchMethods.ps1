function Add-SearchMethods {
    param ($DomainReport)
    
    $searchUsers = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Users) {
            Write-Log "No user data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Users | Where-Object {
            $_.SamAccountName -like "*$SearchTerm*" -or
            $_.DisplayName -like "*$SearchTerm*" -or
            $_.EmailAddress -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No users found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    $searchComputers = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Computers) {
            Write-Log "No computer data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Computers | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.IPv4Address -like "*$SearchTerm*" -or
            $_.DNSHostName -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No computers found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    $searchGroups = {
        param([Parameter(Mandatory)][string]$SearchTerm)
        
        if (-not $this.DomainObjects.Groups) {
            Write-Log "No group data available to search" -Level Warning
            return $null
        }
        
        $results = $this.DomainObjects.Groups | Where-Object {
            $_.Name -like "*$SearchTerm*" -or
            $_.Description -like "*$SearchTerm*" -or
            $_.GroupCategory -like "*$SearchTerm*" -or
            $_.GroupScope -like "*$SearchTerm*"
        }
        
        if (-not $results) {
            Write-Log "No groups found matching search term: '$SearchTerm'" -Level Info
            return $null
        }
        return $results
    }

    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchUsers" -Value $searchUsers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchComputers" -Value $searchComputers -Force
    Add-Member -InputObject $DomainReport -MemberType ScriptMethod -Name "SearchGroups" -Value $searchGroups -Force
}
