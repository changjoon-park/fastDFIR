function Get-CollectionStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [object[]]$Data,
        [string]$ObjectType
    )
    
    $stats = [PSCustomObject]@{
        ObjectType     = $ObjectType
        TotalCount     = $Data.Count
        OUDistribution = @{}
    }
    
    # Count objects per OU
    $Data | ForEach-Object {
        $ouPath = ($_.DistinguishedName -split ',(?=OU=)' | Where-Object { $_ -match '^OU=' }) -join ','
        if (-not $ouPath) { $ouPath = "No OU (Root)" }
        
        if ($stats.OUDistribution.ContainsKey($ouPath)) {
            $stats.OUDistribution[$ouPath]++
        }
        else {
            $stats.OUDistribution[$ouPath] = 1
        }
    }
    
    return $stats
}