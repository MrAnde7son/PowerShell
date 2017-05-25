<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>
function Remove-ObjectPermissions
{
<#
    .SYNOPSIS
        Removes the ability of a given active directory object to read privileged users properties.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER SID
        The SID of the object to remove permissions.

    .EXAMPLE 
        PS C:\> Remove-ReadPermissions -SID
        Removes read permissions of a given object by its SID.
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$true)]
        [String]
        $SID
    )

    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule([System.Security.Principal.IdentityReference]([System.Security.Principal.SecurityIdentifier]$SID),[System.DirectoryServices.ActiveDirectoryRights]"GenericAll",[System.Security.AccessControl.AccessControlType]"Deny",,[System.DirectoryServices.ActiveDirectorySecurityInheritance]"All")

    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains | % {$_.GetDirectoryEntry() })
    $Results = @()

    foreach ($Domain in $DomainList){
        $Searcher = New-Object System.DirectoryServices.DirectorySearcher($Domain)
        $Searcher.filter = '( |(name=Domain Admins)(name=Administrators)(name=krbtgt)(name=Enterprise Admins))'
        $Searcher.PageSize = 1000
        $Searcher.SearchScope = "Subtree"
        $Results += $Searcher.FindAll()

    }

    foreach ($object in $Results){ 
        $object.GetDirectoryEntry().ObjectSecurity.AddAccessRule($ACE)
    }
}
