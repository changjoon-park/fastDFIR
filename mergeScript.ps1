$SourceDirectory = ".\fastDFIR"
$OutputFile = ".\MergedScript.ps1"

# Create or clear the output file
Set-Content -Path $OutputFile -Value "# Merged Script - Created $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n"

# Get all ps1 files recursively
$files = Get-ChildItem -Path $SourceDirectory -Filter "*.ps1" -Recurse

foreach ($file in $files) {
    # Add a header comment for each file
    Add-Content -Path $OutputFile -Value "`n#region $($file.Name)`n"
    
    # Get the content and add it to the merged file
    $content = Get-Content -Path $file.FullName
    Add-Content -Path $OutputFile -Value $content
    
    # Add an end region marker
    Add-Content -Path $OutputFile -Value "`n#endregion`n"
}

Write-Host "Merged $($files.Count) files into $OutputFile"