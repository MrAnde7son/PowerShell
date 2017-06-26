<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Invoke-PtHDetection
{
<#
    .SYNOPSIS
        Returns potentially Pth events through event log parsing. credit to @HackingDave for the detection technique.
        
        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .PARAMETER 

    .EXAMPLE Invoke-PtHDetection
       
    #>

    [CmdletBinding()]
    param
    (

    )

    $pthEvents = @()
    $Events = Get-WinEvent -FilterHashtable @{LogName='Security';'Id'=4624,4625}
    foreach ($event in $Events){
        $eventxml = ([xml]$event.ToXml()).Event.EventData.Data
        $LogonType = $eventxml.GetValue(8).'#text'
        $LogonProcessName = $eventxml.GetValue(9).'#text'
        $KeyLength = $eventxml.GetValue(15).'#text'
        if ($LogonType -eq 3 -and $LogonProcessName -eq 'NtLmSsp' -and $KeyLength -eq 0){
            $pthEvents += $event
        }
    }
    return $pthEvents
}
