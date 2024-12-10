function Find-SuspiciousSPNs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Computers,
        [object[]]$Users,
        [hashtable]$KnownGoodSPNs = @{
            'WSMAN'               = 'Windows Remote Management'
            'DNS'                 = 'Domain Name Service'
            'HOST'                = 'Host Service'
            'GC'                  = 'Global Catalog'
            'TERMSRV'             = 'Terminal Services'
            'RestrictedKrbHost'   = 'Kerberos Restricted Delegation'
            'exchangeAB'          = 'Exchange Address Book'
            'ldap'                = 'LDAP Service'
            'MSServerClusterMgmt' = 'Failover Cluster Management'
            'SMTP'                = 'Simple Mail Transfer Protocol'
            'MSSQLSvc'            = 'SQL Server'
            'HTTP'                = 'Web Services'
        },
        [string[]]$SuspiciousPatterns = @(
            '\s+',
            '[;|&]',
            '/\.\.', 
            '/cmd\.exe',
            '/powershell\.exe',
            '\.(ps1|bat|cmd|vbs|js)$'
        )
    )

    $results = @()
    
    # Process both computers and users
    $allObjects = @()
    $allObjects += $Computers | Select-Object @{N = 'Name'; E = { $_.Name } }, 
    @{N = 'Type'; E = { 'Computer' } }, 
    'ServicePrincipalNames'
    $allObjects += $Users | Select-Object @{N = 'Name'; E = { $_.SamAccountName } }, 
    @{N = 'Type'; E = { 'User' } }, 
    'ServicePrincipalNames'

    foreach ($obj in $allObjects) {
        if ($obj.ServicePrincipalNames) {
            $suspiciousSPNs = @{}
            $foundSuspicious = $false
            
            foreach ($spn in $obj.ServicePrincipalNames) {
                $prefix = $spn.Split('/')[0]
                $isSuspicious = $false
                $reason = ""

                # Check if it's an unknown SPN prefix
                if (-not $KnownGoodSPNs.ContainsKey($prefix)) {
                    $reason = "Unknown SPN prefix: $prefix"
                    $isSuspicious = $true
                }

                # Check for suspicious patterns even in known good SPNs
                foreach ($pattern in $SuspiciousPatterns) {
                    if ($spn -match $pattern) {
                        $reason = "Suspicious pattern found: $pattern"
                        $isSuspicious = $true
                        break
                    }
                }

                if ($isSuspicious) {
                    $suspiciousSPNs[$spn] = $reason
                    $foundSuspicious = $true
                }
            }

            if ($foundSuspicious) {
                $results += [PSCustomObject]@{
                    ObjectName     = $obj.Name
                    ObjectType     = $obj.Type
                    SuspiciousSPNs = $suspiciousSPNs
                    TimeDetected   = Get-Date
                    RiskLevel      = if ($obj.Type -eq 'User') { 'High' } else { 'Medium' }
                }
            }
        }
    }

    return $results | Sort-Object ObjectName, ObjectType
}