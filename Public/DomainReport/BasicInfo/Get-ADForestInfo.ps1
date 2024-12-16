function Get-ADForestInfo {
    [CmdletBinding()]
    param(
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving AD forest information from AD..." -Level Info

        # Define the filter and properties
        $filter = '*'  # Not used by Get-ADForest, but kept for compatibility
        $properties = @(
            'Name',
            'ForestMode',
            'SchemaMaster',
            'DomainNamingMaster',
            'GlobalCatalogs',
            'Sites',
            'Domains',
            'RootDomain',
            'SchemaNamingContext',
            'DistinguishedName'
        )

        # Define the processing script
        $processingScript = {
            param($forest)

            $info = [PSCustomObject]@{
                Name                = $forest.Name
                ForestMode          = $forest.ForestMode
                SchemaMaster        = $forest.SchemaMaster
                DomainNamingMaster  = $forest.DomainNamingMaster
                GlobalCatalogs      = $forest.GlobalCatalogs
                Sites               = $forest.Sites
                Domains             = $forest.Domains
                RootDomain          = $forest.RootDomain
                SchemaNamingContext = $forest.SchemaNamingContext
                DistinguishedName   = $forest.DistinguishedName
            }

            # Add a ToString method
            Add-Member -InputObject $info -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); ForestMode=$($this.ForestMode); SchemaMaster=$($this.SchemaMaster); GlobalCatalogs=$($this.GlobalCatalogs.Count); Domains=$($this.Domains.Count)"
            } -Force

            $info
        }

        # Since Get-ADForest returns a single object, handle accordingly
        Write-Log "Retrieving Forest Information..." -Level Info

        $forestInfo = Invoke-ADRetrievalWithProgress -ObjectType "ForestInfo" `
            -Filter $filter `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Forest Information"

        return $forestInfo
    }
    catch {
        Write-Log "Error retrieving forest information: $($_.Exception.Message)" -Level Error
        return $null
    }
}