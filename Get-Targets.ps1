function Get-Targets {
    [CmdletBinding()]
    param (
        [Parameter()]
        [String]$AccountName,
        [String]$query
    )
    $instance = "SQL\Audit"
    $DBName = "SonicWallAudit"

    $credentials = (Get-ITGluePasswords -organization_id "2426633" -id "15564490").data.attributes
    $creds = New-Object System.Management.Automation.PsCredential($credentials.username, (ConvertTo-SecureString $credentials.password -AsPlainText -force ))
   
    switch ($query) {

        "BasicAuth" { Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "select * From accounts where MFAEnabled='N' AND Active='Y' AND Gen7='N'" }
        "TFA"   {Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "select * From accounts where MFAEnabled='Y' AND Active='Y' AND Gen7='N'"}
        "GeoIP" {
            Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "Select 
        GeoIP_Audit.AccountName AS [GeoIP_Audit AccountName]
        ,GeoIP_Audit.MissingCountries AS [GeoIP_Audit MissingCountries] From GeoIP_Audit inner join accounts on GeoIP_Audit.AccountName = Accounts.AccountName where GeoIP_Audit.MissingCountries IS NOT NULL AND Accounts.MFAEnabled='N'"
        }
        "Account" { Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query " SELECT * From Accounts WHERE AccountName LIKE '$($AccountName)%'" }
        "All" { Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query " SELECT * From Accounts WHERE Active='Y'" }
    }
}