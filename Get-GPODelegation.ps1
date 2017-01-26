<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Get-GPODelegation
{
<#
    .SYNOPSIS
        Finds users with write permissions on GPO objects which may allow privilege escalation within the domain.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER GPOName
        The GPO display name to query for, wildcards accepted.  

    .PARAMETER Domain

    .PARAMETER DomainController

    .PARAMETER ADSPath

    .PARAMETER PageSize

    .EXAMPLE 
        PS C:\> Get-GPODelegation
        Returns all GPO delegations in current forest.

    .EXAMPLE 
        PS C:\> Get-GPODelegation -GPOName
        Returns all GPO delegations on a given GPO.
#>
    [CmdletBinding()]
    Param (
        [String]
        $GPOName = '*',

        [String]
        $Domain,

        [String]
        $DomainController,

        [String]
        $ADSPath,

        [ValidateRange(1,10000)] 
        [Int]
        $PageSize = 200
    )

    $Exclusions = @("SYSTEM","Domain Admins","Enterprise Admins","CREATOR OWNER")

    if ($GPOName){

    }

    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($objForest.Domains)
    $Domains = $DomainList | foreach { $_.name }
    foreach ($Domain in $Domains) {
        $strFilter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $objDomain = New-Object System.DirectoryServices.DirectoryEntry
        $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
        $objSearcher.SearchRoot = $objDomain
        $objSearcher.Filter = $strFilter
        $objSearcher.PageSize = $PageSize
        $objSearcher.SearchScope = "Subtree"
        $listGPO = $objSearcher.FindAll()
        foreach ($gpo in $listGPO){
            $ACL = (([ADSI]$gpo.path).ObjectSecurity).Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow"}  | ? {$_.IdentityReference -notmatch "SYSTEM" -and $_.IdentityReference -notmatch "Enterprise Admins" -and $_.IdentityReference -notmatch "Domain Admins" -and $_.IdentityReference -notmatch "CREATOR OWNER"}
            $GpoACL = New-Object psobject
            $GpoACL | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
            $GpoACL | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
            $GpoACL | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
            $GpoACL | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
            $GpoACL
        }
    }
}


