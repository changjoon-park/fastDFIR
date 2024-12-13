# Check and import ActiveDirectory module first
try {
    if (-not (Get-Module -Name ActiveDirectory -ErrorAction SilentlyContinue)) {
        Import-Module ActiveDirectory -ErrorAction Stop
        Write-Host "ActiveDirectory module imported successfully" -ForegroundColor Green
    }
}
catch [System.IO.FileNotFoundException] {
    Write-Error "ActiveDirectory module not found. Please install RSAT tools or enable the Active Directory PowerShell features."
    return
}
catch {
    Write-Error "Failed to import ActiveDirectory module: $($_.Exception.Message)"
    return
}

# Import configuration
. "$PSScriptRoot\Config\config.ps1"
. "$PSScriptRoot\Private\Helpers\Initialize-Environment.ps1"
. "$PSScriptRoot\Private\Helpers\Initialize-ADData.ps1"

Initialize-Environment
Initialize-ADData

# fastDFIR.psm1
$Public = @(Get-ChildItem -Path $PSScriptRoot\Public -Recurse -Filter "*.ps1")
$Private = @(Get-ChildItem -Path $PSScriptRoot\Private -Recurse -Filter "*.ps1")

# Dot source the files
foreach ($import in @($Public + $Private)) {
    try {
        . $import.FullName
    }
    catch {
        Write-Error "Failed to import function $($import.FullName): $_"
    }
}

# Export public functions
Export-ModuleMember -Function $Public.BaseName