function Get-ADTrustInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$RootDomain
    )
    
    try {
        Write-Log "Retrieving AD trust information..." -Level Info
        
        Get-ADTrust -Filter * -Server $RootDomain -ErrorAction SilentlyContinue | 
        ForEach-Object {
            [PSCustomObject]@{
                Name      = $_.Name
                Source    = $_.Source
                Target    = $_.Target
                TrustType = $_.TrustType
                Direction = $_.Direction
                TGTQuota  = $_.TGTQuota
                Status    = try {
                    Test-ADTrust -Identity $_.Name -ErrorAction Stop
                    "Valid"
                }
                catch {
                    "Invalid: $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}
