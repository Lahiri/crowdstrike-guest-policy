@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'CheckCrowdStrike.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = 'efb60a6b-9087-4f4f-9bc7-6fb97bb83f0e'

    # Author of this module
    Author = 'Microsoft Corporation'

    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'

    # Copyright statement for this module
    Copyright = ''

    # Description of the functionality provided by this module
    Description = 'Ensure CrowdStrike Falcon Antivirus is installed and running.'

    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '5.0'

    # Functions to export from this module
    FunctionsToExport = @('Get-FalconStatus','Set-FalconStatus','Test-FalconStatus')

    # DSC Resources to export from this module
    DscResourcesToExport = @('CheckCrowdStrike')

    # Private data to pass to the module specified in RootModule/ModuleToProcess.
    # This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            # Tags = @(Power Plan, Energy, Battery)

            # A URL to the license for this module.
            # LicenseUri = ''

            # A URL to the main website for this project.
            # ProjectUri = ''

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

        } # End of PSData hashtable

    }
}