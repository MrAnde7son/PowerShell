<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>
function Invoke-WinRMRestriction
{
<#
    .SYNOPSIS
        Denies access for a specified object to WinRM listener, meaning the specified object wouldn't be able to use winrm against the system.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER SID
        The SID of the object to remove permissions.

    .EXAMPLE 
        PS C:\> Invoke-WinRMRestriction -SID
        Removes permissions of a given object by its SID.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [string]
        $SID
        )
    $sddl = (Get-Item WSMAN:\localhost\Service\RootSDDL).Value
    $SD = New-Object -TypeName System.Security.AccessControl.RawSecurityDescriptor -ArgumentList $sddl
    $NewACE = New-Object System.Security.AccessControl.CommonAce([System.Security.AccessControl.AceFlags]::None,[System.Security.AccessControl.AceQualifier]::AccessDenied,268435456,$SID,$false,$null)
    $SD.DiscretionaryAcl.InsertAce($SD.DiscretionaryAcl.Count,$NewACE)
    Set-Item WSMan:\localhost\Service\RootSDDL -Value $SD.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All) -Force
}
