<#
    Author: Itamar Mizrahi (@Zecured)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Get-GPODelegation
{
<#
    .SYNOPSIS
        Finds users with write permissions on GPO objects.
        Author: Itamar Mizrahi (@Zecured)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .EXAMPLE 
       
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$False, Position=0, ValueFromPipeline=$True)]
        [string]$Domain = $env:USERDOMAIN

    )

    $gpolist = Get-GPO -All
    foreach ($gpo in $gpolist)
    {
        Write-Host "GPO Name: " + $gpo.DisplayName
        Get-GPPermissions -Guid $gpo.Id -All| Where-Object {$_.Permission -eq "GpoEditDeleteModifySecurity"}
    }
}