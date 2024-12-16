function Add-DomainReportMethods {
    param (
        [Parameter(Mandatory)]
        [PSCustomObject]$DomainReport
    )
    
    # Add ToString methods
    Add-ToStringMethods -DomainReport $DomainReport

    # Add Export methods
    Add-ExportMethod -DomainReport $DomainReport
    
    # Add Search methods
    Add-SearchMethods -DomainReport $DomainReport
    
    # Add Network methods
    Add-NetworkMethods -DomainReport $DomainReport
    
    # Add Security methods
    Add-SecurityMethods -DomainReport $DomainReport
}

