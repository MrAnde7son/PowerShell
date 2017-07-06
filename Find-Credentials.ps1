# Potential credentials files
function Find-CredFiles {
    return (Get-ChildItem c:\ -Recurse -Include *pass*, *cred*, *.config*, *vnc* -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer } | select fullname).fullname
} 

# Files with 'password' string
function Find-PasswordFiles {
    $passfiles = Get-ChildItem c:\ -Recurse -Include *.xml, *.ini, *.txt -ErrorAction SilentlyContinue | Select-String -pattern "password" -ErrorAction SilentlyContinue
    $passlist = @()
    foreach ($match in $passfiles){
        $obj = New-Object psobject 
        $obj | Add-Member NoteProperty 'FilePath' $match.Path
        $obj | Add-Member NoteProperty 'LineNumber' $match.LineNumber
        $obj | Add-Member NoteProperty 'Line' $match.Line
        $passlist += $obj
    }
    return $passlist
}

# Registry values with 'password' string
function Find-RegPasswords{
    return Get-ChildItem -path HKLM:\,HKCU:\ -Recurse -ErrorAction SilentlyContinue | % { $key=$_;$_.GetValueNames() | ? { $_ -match 'password' } | %{ Get-ItemProperty $key.pspath -Name $_ | select -ExcludeProperty PSProvider,PSChildName,PSParentPath } }
}


