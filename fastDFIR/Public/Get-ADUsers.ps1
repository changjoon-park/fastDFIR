function Get-ADUsers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$IncludeDisabled
    )
    
    try {
        Write-Log "Retrieving user accounts..." -Level Info
        Show-ProgressHelper -Activity "AD Inventory" -Status "Initializing user retrieval..."
        
        $filter = if ($IncludeDisabled) { "*" } else { "Enabled -eq 'True'" }
        
        $properties = @(
            'SamAccountName',
            'DisplayName',
            'EmailAddress',
            'Enabled',
            'LastLogonDate',
            'PasswordLastSet',
            'PasswordNeverExpires',
            'PasswordExpired',
            'AccountExpirationDate',
            'DistinguishedName'  # Added for OU tracking
        )
        
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Get-ADObjects -ObjectType "Users" -Objects $allUsers -ProcessingScript {
            param($user)
            $user | Select-Object $properties
        }
        
        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType "Users"
        Write-Host "`n=== User Collection Statistics ==="
        Write-Host "Total Users: $($stats.TotalCount)"
        Write-Host "Enabled Users: $(($users | Where-Object { $_.Enabled }).Count)"
        Write-Host "Disabled Users: $(($users | Where-Object { -not $_.Enabled }).Count)"
        Write-Host "`nDistribution by OU:"
        $stats.OUDistribution.GetEnumerator() | Sort-Object Name | ForEach-Object {
            Write-Host ("{0,-50} : {1,5}" -f $_.Key, $_.Value)
        }
        
        if ($Export) {
            if (-not (Test-Path $ExportPath)) {
                New-Item -ItemType Directory -Path $ExportPath -Force
            }
            $exportFile = Join-Path $ExportPath "Users_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $users | Export-Csv $exportFile -NoTypeInformation
            Write-Log "Users exported to $exportFile" -Level Info
        }
        
        Show-ProgressHelper -Activity "AD Inventory" -Status "User retrieval complete" -Completed
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}