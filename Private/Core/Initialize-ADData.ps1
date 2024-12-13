function Initialize-ADData {

    Write-Log "Initializing AD data cache..."

    # Define property sets for each object type
    $userProperties = @(
        'SamAccountName',
        'DistinguishedName',
        'Enabled',
        'Created',
        'MemberOf',
        'ServicePrincipalNames',
        'EmailAddress',
        'DisplayName',
        'PasswordLastSet',
        'PasswordNeverExpires',
        'PasswordExpired',
        'LastLogonDate'
    )

    $computerProperties = @(
        'Name',
        'IPv4Address',
        'DistinguishedName',
        'OperatingSystem',
        'OperatingSystemVersion',
        'OperatingSystemServicePack',
        'Enabled',
        'LastLogonDate',
        'Created',
        'Modified',
        'DNSHostName',
        'SID',
        'ServicePrincipalNames',
        'MemberOf'
    )

    $groupProperties = @(
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
    # Organizational Units
    # Typical OU properties are minimal; if more are needed, add them here.
    $ouProperties = @(
        'DistinguishedName',
        'Name',
        'Description',
        'Created',
        'Modified'
    )

    # Domain Controllers
    # Common properties you might need:
    $dcProperties = @(
        'DNSHostName',
        'IPv4Address',
        'HostName',
        'Site',
        'IsGlobalCatalog',
        'Enabled',
        'OperatingSystem',
        'OperatingSystemVersion'
    )

    # Replication Sites
    # `Get-ADReplicationSite` supports a limited set of properties by default.
    # We'll specify common properties if needed:
    $siteProperties = @(
        'DistinguishedName',
        'Name',
        'Location',
        'Description',
        'Created',
        'Modified'
    )

    # Trusts
    # `Get-ADTrust` supports -Properties. Use * to get all properties or customize:
    $trustProperties = @(
        'Name',
        'Source',
        'Target',
        'TrustType',
        'Direction',
        'DisallowTransivity',
        'IntraForest',
        'TGTQuota',
        'DistinguishedName'
    )

    # Retrieve and store objects
    $script:AllUsers = Get-ADUser -Filter * -Properties $userProperties
    $script:AllComputers = Get-ADComputer -Filter * -Properties $computerProperties
    $script:AllGroups = Get-ADGroup -Filter * -Properties $groupProperties
    $script:AllOUs = Get-ADOrganizationalUnit -Filter * -Properties $ouProperties
    $script:AllDCs = Get-ADDomainController -Filter * -Properties $dcProperties
    $script:ForestInfo = Get-ADForest  # no -Properties available
    $script:AllSites = Get-ADReplicationSite -Filter * -Properties $siteProperties
    $script:AllSubnets = Get-ADReplicationSubnet -Filter * -Properties *
    $script:AllSiteLinks = Get-ADReplicationSiteLink -Filter * -Properties *
    $script:AllReplConnections = Get-ADReplicationConnection -Filter * -Properties *
    $script:AllTrusts = Get-ADTrust -Filter * -Properties $trustProperties

    # Summary log
    Write-Log ("AD data cache initialized: " +
        "Users: $($script:AllUsers.Count), " +
        "Computers: $($script:AllComputers.Count), " +
        "Groups: $($script:AllGroups.Count), " +
        "OUs: $($script:AllOUs.Count), " +
        "DomainControllers: $($script:AllDCs.Count), " +
        "Sites: $($script:AllSites.Count), " +
        "Trusts: $($script:AllTrusts.Count)")

}