Function Invoke-WMIRestriction
{
<#
    .SYNOPSIS
        Modifies WMI root namespace ACL to deny all access of specific user, in order to mitigate WMI lateral movement of specific privileged users (not supposed to use WMI).
        
        Author: Itamar Mizrahi (@Zecured)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER Username
    Username to deny access for.

    .PARAMETER ComputerName
    Remote computer to edit ACL on.

    .EXAMPLE Invoke-WMIRestriction -Username 
    Deny access for user specified on local computer

    .EXAMPLE Invoke-WMIRestriction -Username -ComputerName
       
#>
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True, ValueFromPipeline=$True)]
        [string]$Username,
        [parameter(Mandatory=$False, ValueFromPipeline=$True)]
        [string]$ComputerName = "."
    )

    # Gets all user properties
    $Searcher = New-Object System.DirectoryServices.DirectorySearcher
    $Searcher.filter = "(samaccountname=$Username)"
    $Searcher.SearchScope = "Subtree"
    $account = $Searcher.FindAll()
    $objectsid = [byte[]]($account.Properties.objectsid)[0]
    $SecurityIdentifier = New-Object System.Security.Principal.SecurityIdentifier $objectsid,0
    $SID = $SecurityIdentifier.translate([Security.Principal.SecurityIdentifier])

    # Initialize objects
    $Trustee = ([WMIClass] "Win32_Trustee").CreateInstance() 
    $Ace = ([WMIClass] "Win32_ACE").CreateInstance() 

    $Trustee.Name = $account.Properties.samaccountname
    $Trustee.Domain = $Searcher.SearchRoot.dc
    $Trustee.SID = $objectsid 
    $Trustee.SIDString = $SID.Value
    $Trustee.SidLength = $SID.BinaryLength

    $Ace.AccessMask = 393279 # ALL ACCESS
    $Ace.AceFlags = 0
    $Ace.AceType = 1 # Deny
    $Ace.Trustee = $Trustee

    # Adds ace to root namespace acl
    $GetSecurityDescriptor = Invoke-WmiMethod -ComputerName $ComputerName -Namespace "root" -Path "__SystemSecurity=@" -Name GetSecurityDescriptor
    if ($GetSecurityDescriptor.ReturnValue -ne 0){
        throw "GetSecurityDescriptor failed." + $GetSecurityDescriptor.ReturnValue
    }
    $acl = $GetSecurityDescriptor.Descriptor
    $acl.DACL += $ace.psobject.immediateBaseObject
    $SetSecurityDescriptor = Invoke-WmiMethod -ComputerName $ComputerName -Namespace "root" -Path "__SystemSecurity=@" -Name SetSecurityDescriptor -ArgumentList $acl.psobject.ImmediateBaseObject
    if ($SetSecurityDescriptor.ReturnValue -ne 0){
        throw "SetSecurityDescriptor failed." + $SetSecurityDescriptor.ReturnValue
    }
}