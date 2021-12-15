function Get-Targets {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]$AccountName,
        [String]$query
    )
   
   
    switch ($query) {

        "BasicAuth" { Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query "select * From accounts where MFAEnabled='N' AND Active='Y' AND Gen7='N'" }
        "TFA"       { Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query "select * From accounts where MFAEnabled='Y' AND Active='Y' AND Gen7='N' AND TFA IS NOT NULL"}
        "GeoIP"     {
                      Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query "Select GeoIP_Audit.AccountName AS [GeoIP_Audit AccountName]
                     ,GeoIP_Audit.MissingCountries AS [GeoIP_Audit MissingCountries] From GeoIP_Audit inner join accounts on GeoIP_Audit.AccountName = Accounts.AccountName where GeoIP_Audit.MissingCountries IS NOT NULL AND Accounts.MFAEnabled='N'"
        }
        "Account"   { Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query " SELECT * From Accounts WHERE AccountName LIKE '$($AccountName)%'" }
        "All"       { Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query " SELECT * From Accounts WHERE Active='Y'" }
    }
}