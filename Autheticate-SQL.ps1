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
