# Import configuration
$script:Config = @{
    ExportPath          = ".\Reports"
    LogPath             = ".\Logs"
    MaxConcurrentJobs   = 5
    RetryAttempts       = 3
    RetryDelaySeconds   = 5
    DefaultExportFormat = "JSON"
    VerboseOutput       = $false
    MaxQueryResults     = 10000
}

function Initialize-ADData {
    # Ensure the AD module is imported
    Import-ADModule

    Write-Log "Initializing AD data cache..."
    
    # Retrieve and store users (with all needed properties in advance)
    $script:AllUsers = Get-ADUser -Filter * -Properties SamAccountName, DistinguishedName, Enabled, Created, MemberOf, ServicePrincipalNames, EmailAddress, DisplayName, PasswordLastSet, PasswordNeverExpires, PasswordExpired, LastLogonDate

    # Retrieve and store computers
    $script:AllComputers = Get-ADComputer -Filter * -Properties IPv4Address, DistinguishedName, OperatingSystem, OperatingSystemVersion, Enabled, LastLogonDate, Created, Modified, DNSHostName, ServicePrincipalNames, MemberOf

    # Retrieve and store groups
    $script:AllGroups = Get-ADGroup -Filter * -Properties Description, GroupCategory, GroupScope, Members, MemberOf, DistinguishedName, Created, Modified

    Write-Log "AD data cache initialized. Users: $($script:AllUsers.Count), Computers: $($script:AllComputers.Count), Groups: $($script:AllGroups.Count)"
}