function Get-ADUsers {
    [CmdletBinding()]
    param(
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$IncludeDisabled
    )
    
    try {
        Write-Log "Retrieving user accounts..." -Level Info
        # Make sure to provide both Activity and Status here
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
            'AccountExpirationDate'
        )
        
        # Make sure to provide both Activity and Status here
        Show-ProgressHelper -Activity "AD Inventory" -Status "Getting users..."
        $allUsers = Invoke-WithRetry -ScriptBlock {
            Get-ADUser -Filter $filter -Properties $properties -ErrorAction Stop
        }
        
        $users = Process-ADObjects -ObjectType "Users" -Objects $allUsers -ProcessingScript {
            param($user)
            $user | Select-Object $properties
        }
        
        if ($Export) {
            # Make sure to provide both Activity and Status here
            Show-ProgressHelper -Activity "AD Inventory" -Status "Exporting user data..."
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
    catch [Microsoft.ActiveDirectory.Management.ADServerDownException] {
        Write-Log "Domain controller is not accessible" -Level Error
        Show-ErrorBox "Domain controller is not accessible. Please check network connectivity."
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}
