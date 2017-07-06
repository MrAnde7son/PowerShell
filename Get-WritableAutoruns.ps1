function Get-WritableAutoruns
{
<#
    .SYNOPSIS
        Get all writable autoruns in order to detect potential privesc.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER 

    .EXAMPLE 
        PS C:\> Get-WriteableAutoruns
#>
    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Downloads and extracts autorunsc
    Invoke-WebRequest https://download.sysinternals.com/files/Autoruns.zip -OutFile autoruns.zip
    [System.IO.Compression.ZipFile]::ExtractToDirectory("autoruns.zip",".\autoruns")
    Set-Location .\autoruns
    # Search for all writable autoruns' files.
    $autoruns = ConvertFrom-Csv (autorunsc.exe -nobanner -a * -c)
    foreach ($obj in $autoruns){
        $location = $obj.'Entry Location' + "\" + $obj.Entry
        $imagepath = $obj.'Image Path'
        if ($imagepath -match "c:\\"){
            Try { 
                [System.IO.File]::OpenWrite($imagepath).close()
                $obj
            }
            Catch{}
        }
    }
    Set-Location .\..\
    Remove-Item autoruns.zip -Force
    Remove-Item autoruns -Recurse -Force
}