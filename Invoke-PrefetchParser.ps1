<#
    Author: Itamar Mizrahi (@Zecured)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>
Function Invoke-PrefetchParser{
<#
    .SYNOPSIS
        Parses prefetch files on live system and returns the result.
        Author: Itamar Mizrahi (@Zecured)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .PARAMETER Prefetch
     Specify prefetch file to parse. default is all the prefetch directory.

    .EXAMPLE 
       
#>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory=$False, ValueFromPipeline=$True)]
        [string]$Prefetch="C:\Windows\Prefetch"
    )

    $versions = @{"11-00-00-00" = "Windows XP";"17-00-00-00" = "Windows 7";"1A-00-00-00" = "Windows 8/8.1";"1E-00-00-00" = "Windows 10"}

    $prefList = @()
    $item = Get-Item $prefetch
    if ($item.PSIsContainer){
        $prefList = Get-ChildItem -Recurse $item -Filter *.pf
    }
    else {
        $prefList = Get-Item $prefetch
    }

    $parsedList = @()
    foreach ($pref in $prefList){
        $parsedPref = New-Object psobject
        $parsedPref | Add-Member NoteProperty 'PrefetchName' $null
        $parsedPref | Add-Member NoteProperty 'Version' $null
        $parsedPref | Add-Member NoteProperty 'FileSignature' $null
        $parsedPref | Add-Member NoteProperty 'FileSize' $null
        $parsedPref | Add-Member NoteProperty 'ApplicationName' $null
        $parsedPref | Add-Member NoteProperty 'FilePathHash' $null
        $parsedPref | Add-Member NoteProperty 'ApplicationRunCount' $null
        $parsedPref | Add-Member NoteProperty 'DependencyCount' $null
        $parsedPref | Add-Member NoteProperty 'DependencyFiles' $null
        $parsedPref | Add-Member NoteProperty 'LastExecutionTime' $null
        $parsedPref | Add-Member NoteProperty 'PfCreatedTimestamp' $null
        $parsedPref | Add-Member NoteProperty 'PfModifiedTimestamp' $null
        $parsedPref | Add-Member NoteProperty 'PfAccessedTimestamp' $null
        $content = [System.IO.File]::ReadAllBytes($pref.FullName)
        $parsedPref.PrefetchName = $pref.FullName
        $ver = [System.BitConverter]::ToString($content[0..3])
        $parsedPref.Version = $versions.get_item($ver)
        $parsedPref.FileSignature = [System.Text.Encoding]::ASCII.GetString($content[4..7])
        $parsedPref.FileSize = [convert]::tostring([bitconverter]::touint32($content,12))
        for($i = 16; $i -lt 76; $i += 2 ) { if ($content[$i] -eq 0) { $i--;break }}
        $parsedPref.ApplicationName = [System.Text.Encoding]::Unicode.GetString($content[16..$i])
        $parsedPref.FilePathHash = [convert]::tostring([bitconverter]::touint32($content,76))
        $parsedPref.ApplicationRunCount = [bitconverter]::touint32($content,208)
        $parsedPref.LastExecutionTime = [datetime]::fromfiletime([bitconverter]::touint64($content,128))
        $parsedPref.PfCreatedTimestamp = $pref.CreationTime
        $parsedPref.PfModifiedTimestamp = $pref.LastWriteTime
        $parsedPref.PfAccessedTimestamp = $pref.LastAccessTime
        $offsets 
        for ($i = 84; $i -lt 120; $i += 4){
            $aOffset = [bitconverter]::touint32($content[$i..($i=$i+3)],0)
            $aEntryNum = [bitconverter]::touint32($content[$i++..($i=$i+3)],0)
            $aLength = [bitconverter]::touint32($content[$i++..($i=$i+3)],0)
        }
        $aOffset = [bitconverter]::touint32($content[84..87],0)
        $aEntryNum = [bitconverter]::touint32($content[88..91],0)
        $bOffset = [bitconverter]::touint32($content[92..95],0)
        $bEntryNum = [bitconverter]::touint32($content[96..99],0)
        $cOffset = [bitconverter]::touint32($content[100..103],0)
        $cLength = [bitconverter]::touint32($content[104..107],0)
        $dOffset = [bitconverter]::touint32($content[108..111],0)
        $dEntryNum = [bitconverter]::touint32($content[112..115],0)
        $dLength = [bitconverter]::touint32($content[116..119],0)

        $modules = [System.Text.Encoding]::Unicode.GetString($content[$cOffset..($cOffset + $cLength)])
        $Modlist = $modules.Split([char]0)
        $Modlist = $Modlist[0..($Modlist.Count-2)]
        $parsedPref.DependencyCount = $Modlist.Count
        $parsedPref.DependencyFiles = $Modlist -join ','

        $fOffset = [bitconverter]::touint32($content[($dOffset + 0x1c)..($dOffset + 0x1c + 3)],0)
        $fNum = [bitconverter]::touint32($content[($dOffset + 0x20)..($dOffset + 0x20 + 3)],0)

        $parsedList += $parsedPref
    }
    return $parsedList
}

Function Invoke-PrefetchProcessHollowing {
<#
    .SYNOPSIS
        Returns potectially process hollowing attempts through prefetch analysis
        Author: Itamar Mizrahi (@Zecured)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .PARAMETER 

    .EXAMPLE 
       
#>

    $prefs = Invoke-PrefetchParser
    $prefs | ? {$_.DependencyCount -le 20 -or $_.ApplicationRunCount -eq 1}
}