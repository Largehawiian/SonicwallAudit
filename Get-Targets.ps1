function Get-Targets {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]$AccountName,
        [String]$query
    )
   
    switch ($query) {

        "TFA" { Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "select * From accounts where MFAEnabled='N' AND Active='Y' AND Gen7='N'" }
        "GeoIP" { Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "Select 
        GeoIP_Audit.AccountName AS [GeoIP_Audit AccountName]
        ,GeoIP_Audit.MissingCountries AS [GeoIP_Audit MissingCountries] From GeoIP_Audit inner join accounts on GeoIP_Audit.AccountName = Accounts.AccountName where GeoIP_Audit.MissingCountries IS NOT NULL AND Accounts.MFAEnabled='N'"}
        "Account" { Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query " SELECT * From Accounts WHERE AccountName LIKE '$($AccountName)%'" }
        "All"     {Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query " SELECT * From Accounts WHERE Active='Y'"}
    }
}