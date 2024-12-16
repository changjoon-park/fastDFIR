function Initialize-ADData {
    param(
        [Parameter(Mandatory = $true)]
        [string]$AdminRights,

        [Parameter(Mandatory = $false)]
        [System.Management.Automation.PSCredential]$Credential
    )

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

    $ouProperties = @(
        'DistinguishedName',
        'Name',
        'Description',
        'Created',
        'Modified'
    )

    $siteProperties = @(
        'DistinguishedName',
        'Name',
        'Location',
        'Description',
        'Created',
        'Modified'
    )

    # Build parameter hashtables for each query including optional credentials
    $userParams = @{ Filter = '*'; Properties = $userProperties }
    $computerParams = @{ Filter = '*'; Properties = $computerProperties }
    $groupParams = @{ Filter = '*'; Properties = '*' }
    $gpoParams = @{ All = $true }
    $ouParams = @{ Filter = '*'; Properties = $ouProperties }
    $dcParams = @{ Filter = '*' }
    $forestParams = @{ }
    $siteParams = @{ Filter = '*'; Properties = $siteProperties }
    $subnetParams = @{ Filter = '*'; Properties = '*' }
    $siteLinkParams = @{ Filter = '*'; Properties = '*' }
    $replConnectionParams = @{ Filter = '*'; Properties = '*' }
    $trustParams = @{ Filter = '*'; Properties = '*' }

    if ($Credential) {
        $userParams.Credential = $Credential
        $computerParams.Credential = $Credential
        $groupParams.Credential = $Credential
        $gpoParams.Credential = $Credential
        $ouParams.Credential = $Credential
        $dcParams.Credential = $Credential
        $forestParams.Credential = $Credential
        $siteParams.Credential = $Credential
        $subnetParams.Credential = $Credential
        $siteLinkParams.Credential = $Credential
        $replConnectionParams.Credential = $Credential
        $trustParams.Credential = $Credential
    }

    if ($adminRights.IsADAdmin) {
        Write-Log "AD Admin rights confirmed - collecting all data" -Level Info

        $script:AllUsers = Get-ADUser @userParams
        $script:AllComputers = Get-ADComputer @computerParams
        $script:AllGroups = Get-ADGroup @groupParams
        $script:AllPolicies = Get-GPO @gpoParams
        $script:AllOUs = Get-ADOrganizationalUnit @ouParams
        $script:AllDCs = Get-ADDomainController @dcParams
        $script:ForestInfo = Get-ADForest @forestParams
        $script:AllSites = Get-ADReplicationSite @siteParams
        $script:AllSubnets = Get-ADReplicationSubnet @subnetParams
        $script:AllSiteLinks = Get-ADReplicationSiteLink @siteLinkParams
        $script:AllReplConnections = Get-ADReplicationConnection @replConnectionParams
        $script:AllTrusts = Get-ADTrust @trustParams
    }
    elseif ($AdminRights.IsOUAdmin) {
        Write-Log "OU Admin rights detected - collecting limited data" -Level Info

        $script:AllUsers = Get-ADUser @userParams
        $script:AllComputers = Get-ADComputer @computerParams
        $script:AllGroups = Get-ADGroup @groupParams
    }

    # Summary log
    Write-Log ("AD data cache initialized: " +
        "Users: $($script:AllUsers.Count), " +
        "Computers: $($script:AllComputers.Count), " +
        "Groups: $($script:AllGroups.Count), " +
        "Policies: $($script:AllPolicies.Count), " +
        "OUs: $($script:AllOUs.Count), " +
        "DomainControllers: $($script:AllDCs.Count), " +
        "Sites: $($script:AllSites.Count), " +
        "Trusts: $($script:AllTrusts.Count)")
}