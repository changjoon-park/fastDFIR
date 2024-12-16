function Get-ADTrustInfo {
    [CmdletBinding()]
    param(
        [System.Management.Automation.PSCredential]$Credential
    )
    
    try {
        Write-Log "Retrieving AD trust information from AD..." -Level Info

        # Define the filter and properties
        $filter = '*'
        $properties = @(
            'Name',
            'Source',
            'Target',
            'TrustType',
            'Direction',
            'DisallowTransitivity',
            'IsIntraForest',
            'TGTQuota',
            'DistinguishedName'
        )

        # Define the processing script
        $processingScript = {
            param($trust)

            $trustObject = [PSCustomObject]@{
                Name                 = $trust.Name
                Source               = $trust.Source
                Target               = $trust.Target
                TrustType            = $trust.TrustType
                Direction            = $trust.Direction
                DisallowTransitivity = $trust.DisallowTransitivity
                IsIntraForest        = $trust.IsIntraForest
                TGTQuota             = $trust.TGTQuota
                DistinguishedName    = $trust.DistinguishedName
            }

            # Add a ToString method
            Add-Member -InputObject $trustObject -MemberType ScriptMethod -Name "ToString" -Value {
                "Name=$($this.Name); Source=$($this.Source); Target=$($this.Target); TrustType=$($this.TrustType); Direction=$($this.Direction)"
            } -Force

            $trustObject
        }

        # Invoke the helper function
        return Invoke-ADRetrievalWithProgress -ObjectType "Trusts" `
            -Filter $filter `
            -Properties $properties `
            -Credential $Credential `
            -ProcessingScript $processingScript `
            -ActivityName "Retrieving Trusts"
    }
    catch {
        Write-Log "Error retrieving trust information: $($_.Exception.Message)" -Level Error
        return $null
    }
}