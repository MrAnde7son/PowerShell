Add-Type -assemblyname System.DirectoryServices.AccountManagement
Function Test-ADAuthentication 
{
    param
    ($Username,$Password)
    (new-object DirectoryServices.Directoryentry "",$Username,$Password).psbase.name -ne $null
}