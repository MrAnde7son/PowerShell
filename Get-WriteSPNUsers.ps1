<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Get-WriteSPNUsers
{
<#
    .SYNOPSIS
        Searches and prints users with "Write servicePrincipalName" right.
        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .PARAMETER Domain
     Domain to search, default is current user's domain.

    .EXAMPLE 
       
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$False, Position=0, ValueFromPipeline=$True)]
        [string]$Domain = $env:USERDOMAIN

    )

    $writeSPNUsers = @()
    $users = Get-ADUser -Filter * -Server $DOMAIN | select distinguishedname
    foreach ($user in $users)
    {
        $userAD = "AD:\" + $user.distinguishedname
        $writeSPNUsers += ((Get-Acl $userAD).access | ?{$_.ObjectType -eq "f3a64788-5306-11d1-a9c5-0000f80367c1"} | select IdentityReference).IdentityReference.value
        Write-Host $user.distinguishedname
    }
}


