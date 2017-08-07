<#
    Author: Itamar Mizrahi (@MrAnde7son)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Invoke-ACLScanner
{
<#
    .SYNOPSIS
        Returns all ACE on every object in the current forest.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER 

    .EXAMPLE 
        PS C:\> Invoke-ACLScanner
        Returns all ACE on every object in the current forest.
       
#>
    [CmdletBinding()]
    Param (
        [Parameter( Position = 0)]
        [String]
        $OutFile = '',

        [Parameter( Position = 1)]
        [String]
        $Domain
    )


$ACEDictionary = @()

$Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()

$ExtendedRights = "LDAP://CN=Extended-Rights," + ($Forest.Schema.Name.Split(",")[1..$Forest.Schema.Name.Length] -join ",")
$Entry = New-Object System.DirectoryServices.DirectoryEntry($ExtendedRights)
$Searcher = New-Object System.DirectoryServices.DirectorySearcher($Entry)
$Searcher.SearchScope = "OneLevel"
$ACEs = $Searcher.FindAll()

foreach ($ace in $ACEs){
$entry = New-Object PSObject
$entry | Add-Member NoteProperty 'Name' $ace.Properties.cn
$entry | Add-Member NoteProperty 'Guid' $ace.Properties.rightsguid
$ACEDictionary += $entry
}

$DomainList = @($Forest.Domains | % {$_.GetDirectoryEntry() })
$Results = @()
foreach ($Domain in $DomainList){
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher($Domain)
    $Filter = "(objectCategory=*)"
    $Searcher.Filter = $Filter
    $Searcher.PageSize = 1000
    $Searcher.SearchScope = "Subtree"
    $Results += $Searcher.FindAll()

}

foreach ($entry in $Results){
    $owner = $entry.GetDirectoryEntry().ObjectSecurity.Owner
    $rights = $entry.GetDirectoryEntry().ObjectSecurity.Access
    foreach ($right in $rights){
            $ace = $ACEDictionary | ? { $_.Guid -eq $right.ObjectType}
            if($ace -eq $null){
                $ExtendedRightName = ''
            }
            else{
                $ExtendedRightName = $ace.Name[0]
            }
            $extendedRight = New-Object psobject
            $extendedRight | Add-Member NoteProperty 'Owner' $owner
            $extendedRight | Add-Member NoteProperty 'ActiveDirectoryRights' $right.ActiveDirectoryRights
            $extendedRight | Add-Member NoteProperty 'InheritanceType' $right.InheritanceType
            $extendedRight | Add-Member NoteProperty 'ObjectType' $right.ObjectType
            $extendedRight | Add-Member NoteProperty 'ExtendedRightName' $ExtendedRightName
            $extendedRight | Add-Member NoteProperty 'InheritedObjectType' $right.InheritedObjectType
            $extendedRight | Add-Member NoteProperty 'ObjectFlags' $right.ObjectFlags
            $extendedRight | Add-Member NoteProperty 'AccessControlType' $right.AccessControlType
            $extendedRight | Add-Member NoteProperty 'IdentityReference' $right.IdentityReference
            $extendedRight | Add-Member NoteProperty 'IsInherited' $right.IsInherited
            $extendedRight | Add-Member NoteProperty 'InheritanceFlags' $right.InheritanceFlags
            $extendedRight | Add-Member NoteProperty 'PropagationFlags' $right.None
            if($OutFile -ne '') {
                $extendedRight | Export-Csv -Path $OutFile -Append -force
                }
            else {
                $extendedRight | Export-Csv -Path ".\acl.csv" -Append -force
            }
    }
}


}
# -and $owner -notmatch "A_" -and $owner -notmatch "Domain Admins" -and $owner -notmatch "Enterprise Admins" -and $owner -notmatch "Administrators"
