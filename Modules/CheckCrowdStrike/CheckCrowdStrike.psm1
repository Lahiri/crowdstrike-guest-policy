enum ensure {
    Absent
    Present
}

<#
    This class is used within the DSC Resource to standardize how data
    is returned about the compliance details of the machine.
#>
class Reason {
    [DscProperty()]
    [string] $Code

    [DscProperty()]
    [string] $Phrase
}

<#
    Private Functions
#>

function Get-CrowdstrikeInstallationStatus
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param(
        [Parameter()]
        [System.String]
        $ComputerName = "$env:computername"
    )

    return Get-CimInstance Win32_Product | Where-Object {$_.Name -like "Crowdstrike*"}
}

function Get-EPDSCProcessByReportingExecutable
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    param(
        [Parameter()]
        [System.String]
        $ExecutableName = "CSFalconService"
    )

    $processInfo = $null
    try
    {
        $processInfo = Get-Process -Name $ExecutableName -ErrorAction SilentlyContinue
    }
    catch
    {
        Write-Verbose -Message "Could not find process running executable file {$ExecutableName}"
    }
    return $processInfo
}

<#
    Public Functions
#>
function Get-FalconStatus
{
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter()]
        [System.String]
        [ValidateSet("Running", "Stopped")]
        $Status = "Running",

        [Parameter()]
        [System.String]
        [ValidateSet("Absent", "Present")]
        $Ensure
    )

    Write-Verbose -Message "Getting Information about Crowdstrike"
    $Reasons = @()

    $nullReturn = $PSBoundParameters
    $nullReturn.Ensure = "Absent"
    if ($null -ne $nullReturn.Verbose)
    {
        $nullReturn.Remove("Verbose")
    }

    $OSInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    if ($OSInfo.ProductType -eq 1)
    {
        Write-Verbose -Message "Windows Desktop OS Detected"
        $AntivirusInfo = Get-CrowdstrikeInstallationStatus

        if ($null -eq $AntivirusInfo)
        {
            Write-Verbose -Message "Could not obtain Information about Crowdstrike"

            # Antivirus should be installed but it's not
            if ($Ensure -eq 'Present')
            {
                    $Reasons += @{
                        Code = "epantivirusstatus:epantivirusstatus:antivirusnotinstalled"
                        Phrase = "Crowdstrike should be installed but it's NOT."
                    }
            }
            $nullReturn.Add("Reasons", $Reasons)

            return $nullReturn
        }

        # Antivirus should not be installed but it is
        if ($Ensure -eq 'Absent')
        {
            $Reasons += @{
                Code   = "epantivirusstatus:epantivirusstatus:antivirusinstalled"
                Phrase = "Crowdstrike is installed but it should NOT."
            }
        }

        try
        {
            $executablePathParts = $AntivirusInfo.pathToSignedReportingExe.Split("\")
            $executableName = $executablePathParts[$executablePathParts.Length -1].Split('.')[0]
            $process = Get-EPDSCProcessByReportingExecutable -ExecutableName $executableName

            $statusValue = "Running"
            if ($null -eq $process)
            {
                $statusValue = "Stopped"
            }

            if ($Status -ne $statusValue)
            {
                # Antivirus Agent should be running but its not
                if ($Status -eq 'Running')
                {
                    $Reasons += @{
                        Code   = "epantivirusstatus:epantivirusstatus:agentnotrunning"
                        Phrase = "Antivirus Agent for Crodwstrike Falcon is not running and it SHOULD be."
                    }
                }
                # Antivirus is running and it should not
                else
                {
                    $Reasons += @{
                        Code   = "epantivirusstatus:epantivirusstatus:agentrunning"
                        Phrase = "Antivirus Agent for Crodwstrike Falcon is running and it should NOT be."
                    }
                }
            }

            $result = @{
                AntivirusName = "Crowdstrike Falcon"
                Status        = $statusValue
                Ensure        = "Present"
                Reasons       = $Reasons
            }
        }
        catch
        {
            Write-Verbose -Message "Could not retrieve process running for Antivirus Crodwstrike Falcon"
            $Reasons = @{
                Code   = "epantivirusstatus:epantivirusstatus:unexpected"
                Phrase = "Unexpected Error."
            }
            $nullReturn.Add("Reasons", $Reasons)
            return $nullReturn
        }
    }
    elseif (($OSInfo.ProductType -eq 2) -or ($OSInfo.ProductType -eq 3)) # ProductType=3 Windows Server, ProductType=2 Domain Controller, which is also Windows Server
    {
        Write-Verbose -Message "Windows Server OS Detected"

        # Do a general scan of installed software on the machine just as FYI
        $keys = @("antivirus", "anti-virus", "virus")
        foreach ($key in $keys)
        {
            $instance = get-ciminstance -Namespace 'root/cimv2' `
                -ClassName 'Win32_Product' | Where-Object -FilterScript {$_.Caption -like "*$key*" -or $_.Name -like "*$key*"}

            if ($null -ne $instance)
            {
                Write-Verbose -Message "Found potential Antivirus software {$($instance.Name)} installed"
                break
            }
        }

        # Find processes based on the provided name
        $process = Get-Process | Where-Object -FilterScript {$_.Name -eq "CSFalconService" -or $_.ProcessName -eq "CSFalconService"}

        try
        {
            $statusValue = "Running"
            if ($null -eq $process)
            {
                Write-Verbose -Message "Could not find process for Crodwstrike Falcon"
                # Attempt to find a running service based on the provided name
                $service = Get-Service | Where-Object -FilterScript {$_.Name -like "*Falcon*" -or $_.DisplayName -like "*Falcon*"}

                if ($null -eq $service)
                {
                    Write-Verbose -Message "Could not find service for Crodwstrike Falcon"
                    $statusValue = "Stopped"
                }
                else
                {
                    Write-Verbose -Message "Found service {$($service.DisplayName)}"
                    if ($service.Status -eq "Running")
                    {
                        Write-Verbose -Message "Service {$($service.DisplayName)} is running"
                    }
                    else
                    {
                        Write-Verbose -Message "Service {$($service.DisplayName)} is stopped"
                        $statusValue = "Stopped"
                    }
                }
            }
            else
            {
                Write-Verbose -Message "Found process {$($process.Name)}"
            }

            if ($Status -ne $statusValue)
            {
                # Antivirus Agent should be running but its not
                if ($Status -eq 'Running')
                {
                    $Reasons += @{
                        Code   = "epantivirusstatus:epantivirusstatus:agentnotrunning"
                        Phrase = "Antivirus Agent for Crodwstrike Falcon is not running and it SHOULD be."
                    }
                }
                # Antivirus is running and it should not
                else
                {
                    $Reasons += @{
                        Code   = "epantivirusstatus:epantivirusstatus:agentrunning"
                        Phrase = "Antivirus Agent for Crodwstrike Falcon is running and it should NOT be."
                    }
                }
            }

            $result = @{
                AntivirusName = "Crowdstrike Falcon"
                Status        = $statusValue
                Ensure        = "Present"
                Reasons       = $Reasons
            }
        }
        catch
        {
            Write-Verbose -Message "Could not retrieve process running for Antivirus Crodwstrike Falcon"
            $Reasons = @{
                Code   = "epantivirusstatus:epantivirusstatus:unexpected"
                Phrase = "Unexpected Error."
            }
            $nullReturn.Add("Reasons", $Reasons)
            return $nullReturn
        }
    }
    return $result
}

function Set-FalconStatus
{
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        [ValidateSet("Running", "Stopped")]
        $Status = "Running",

        [Parameter()]
        [System.String]
        [ValidateSet("Absent", "Present")]
        $Ensure
    )

    throw "Calling the Set-TargetResource function for Antivirus Crodwstrike Falcon is not supported"
}

function Test-FalconStatus
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter()]
        [System.String]
        [ValidateSet("Running", "Stopped")]
        $Status = "Running",

        [Parameter()]
        [System.String]
        [ValidateSet("Absent", "Present")]
        $Ensure
    )

    Write-Verbose -Message "Testing Settings of Antivirus Crodwstrike Falcon"

    try
    {
        $CurrentValues = Get-TargetResource @PSBoundParameters

        $result = $true
        if ($CurrentValues.Status -ne $Status -or $CurrentValues.Ensure -ne $Ensure)
        {
            $result = $false

            # Display the reasons for non-compliance
            Write-Verbose -Message 'The current VM is not in compliance due to:'
            foreach ($reason in $CurrentValues.Reasons)
            {
                Write-Verbose -Message "-->$($reason.Phrase)"
            }
        }
        Write-Verbose -Message "Test-TargetResource returned $result"
        return $result
    }
    catch
    {
        Write-Verbose -Message "Something went wrong in the Test-TargetResource method"
    }
    return $false
}

[DscResource()]
class CheckCrowdStrike {
    [DscProperty(Key)]
    [string] $name

    [DscProperty(Mandatory)]
    [ensure] $ensure

    [DscProperty(Mandatory)]
    [string] $status

    [DscProperty(NotConfigurable)]
    [Reason[]] $Reasons

    [CheckCrowdStrike] Get() {
        $get = Get-FalconStatus -Ensure $this.ensure -Status $this.status
        return $get
    }

    [void] Set() {
        $null = Set-FalconStatus -Ensure $this.ensure -Status $this.status
    }

    [bool] Test() {
        $test = Test-FalconStatus -Ensure $this.ensure -Status $this.status
        return $test
    }
}