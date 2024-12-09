function Get-ADDNSInfo {
    [CmdletBinding()]
    param()
    
    try {
        $dnsServer = Get-ADDomainController -Discover | Select-Object -ExpandProperty HostName
        
        # Get all DNS zones
        $zones = Get-DnsServerZone -ComputerName $dnsServer | ForEach-Object {
            $zone = $_
            
            # Get all records for this zone
            $records = Get-DnsServerResourceRecord -ComputerName $dnsServer -ZoneName $zone.ZoneName |
            ForEach-Object {
                [PSCustomObject]@{
                    Name       = $_.HostName
                    RecordType = $_.RecordType
                    RecordData = $_.RecordData.IPv4Address ?? 
                    $_.RecordData.HostNameAlias ??
                    $_.RecordData.DomainName ??
                    $_.RecordData.StringData
                    Timestamp  = $_.Timestamp
                    TimeToLive = $_.TimeToLive
                }
            }
            
            # Special handling for SRV records
            $srvRecords = $records | Where-Object RecordType -eq 'SRV'
            
            [PSCustomObject]@{
                ZoneName               = $zone.ZoneName
                ZoneType               = $zone.ZoneType
                IsDsIntegrated         = $zone.IsDsIntegrated
                IsReverseLookupZone    = $zone.IsReverseLookupZone
                DynamicUpdate          = $zone.DynamicUpdate
                Records                = $records
                ServiceRecords         = $srvRecords
                ReplicationScope       = $zone.ReplicationScope
                DirectoryPartitionName = $zone.DirectoryPartitionName
            }
        }
        
        return [PSCustomObject]@{
            ForwardLookupZones = $zones | Where-Object { -not $_.IsReverseLookupZone }
            ReverseLookupZones = $zones | Where-Object IsReverseLookupZone
        }
    }
    catch {
        Write-Log "Error retrieving DNS information: $($_.Exception.Message)" -Level Error
        return $null
    }
}