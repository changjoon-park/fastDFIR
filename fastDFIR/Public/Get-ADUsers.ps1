function Get-ADUsers {
    [CmdletBinding()]
    param(
        [string]$ObjectType = "Users",
        [switch]$Export,
        [string]$ExportPath = $script:Config.ExportPath,
        [switch]$IncludeDisabled,
        [Parameter()]
        [ValidateSet("JSON", "CSV")]
        [string]$ExportType = "JSON" # Default export type is JSON
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
        
        $users = Get-ADObjects -ObjectType $ObjectType -Objects $allUsers -ProcessingScript {
            param($user)
            $user | Select-Object $properties
        }

        # Generate and display statistics
        $stats = Get-CollectionStatistics -Data $users -ObjectType $ObjectType -IncludeAccessStatus
        $stats.DisplayStatistics()

        # Export data if requested
        Export-ADData -ObjectType $ObjectType -Data $users -ExportPath $ExportPath -Export:$Export -ExportType $ExportType
        
        # Complete progress
        Show-ProgressHelper -Activity "AD Inventory" -Status "User retrieval complete" -Completed
        return $users
    }
    catch {
        Write-Log "Error retrieving users: $($_.Exception.Message)" -Level Error
        Show-ErrorBox "Error retrieving users: $($_.Exception.Message)"
    }
}