function Show-ProgressHelper {
    <#
    .SYNOPSIS
        Displays a progress bar in the console using Write-Progress with additional helper functionality.

    .DESCRIPTION
        The Show-ProgressHelper function is a wrapper around the Write-Progress cmdlet, providing a simplified interface for displaying progress bars.
        It allows for setting activity, status, percentage completion, current operation, and marking the progress as completed.

    .PARAMETER Activity
        The name of the activity displayed in the progress bar. This parameter is mandatory.

    .PARAMETER Status
        The status message displayed alongside the progress bar. Defaults to "Processing...".

    .PARAMETER PercentComplete
        The percentage of completion for the activity. Accepts values from 0 to 100. If not provided or set to a value less than 0, it will be omitted.

    .PARAMETER CurrentOperation
        A brief description of the current operation being performed. This is optional.

    .PARAMETER Completed
        A switch to indicate that the progress is complete. When set, the progress bar will be cleared.

    .EXAMPLE
        # Display a progress bar at 50% completion
        Show-ProgressHelper -Activity "Retrieving Users" -Status "Halfway there..." -PercentComplete 50

    .EXAMPLE
        # Mark the progress as completed
        Show-ProgressHelper -Activity "Retrieving Users" -Completed
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]$Activity,

        [Parameter()]
        [string]$Status = "Processing...",

        [Parameter()]
        [int]$PercentComplete = -1,

        [Parameter()]
        [string]$CurrentOperation = "",

        [Parameter()]
        [switch]$Completed
    )

    # Validate that PercentComplete is within the acceptable range
    if ($PercentComplete -ge 0 -and $PercentComplete -le 100) {
        $validPercent = $true
    }
    elseif ($PercentComplete -lt 0) {
        $validPercent = $false
    }
    else {
        Write-Log "PercentComplete must be between 0 and 100." -Level Warning
        $validPercent = $false
    }

    # Construct the parameters for Write-Progress
    $progressParams = @{
        Activity = $Activity
        Status   = $Status
    }

    if ($Completed) {
        # If the Completed switch is set, clear the progress bar
        Write-Progress @progressParams -Completed
    }
    else {
        # Add PercentComplete if it's valid
        if ($validPercent) {
            $progressParams['PercentComplete'] = $PercentComplete
        }

        # Add CurrentOperation if it's provided
        if (![string]::IsNullOrWhiteSpace($CurrentOperation)) {
            $progressParams['CurrentOperation'] = $CurrentOperation
        }

        # Display the progress bar
        Write-Progress @progressParams
    }
}

#endregion