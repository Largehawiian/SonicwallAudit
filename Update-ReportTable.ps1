function Update-ReportTable {
    [CmdletBinding()]
    param (
        [Parameter()]
        [switch]$MostRecent
    )

    $instance = "SQL\Audit"
    $DBName = "SonicWallAudit"

    $credentials = (Get-ITGluePasswords -organization_id "2426633" -id "15564490").data.attributes
    $creds = New-Object System.Management.Automation.PsCredential($credentials.username, (ConvertTo-SecureString $credentials.password -AsPlainText -force ))
    $Date = (get-date -f yyyy-MM-dd)

    if ($MostRecent){
        $RawdataQuery = "SELECT
        AntiSpyware.Enabled AS [AntiSpyware Enabled]
        ,AntiSpyware.High_Priority_Prevent_All AS [AntiSpyware High_Priority_Prevent_All]
        ,AntiSpyware.High_Priority_Detect_All AS [AntiSpyware High_Priority_Detect_All]
        ,AntiSpyware.Medium_Priority_Prevent_All AS [AntiSpyware Medium_Priority_Prevent_All]
        ,AntiSpyware.Medium_Priority_Detect_All AS [AntiSpyware Medium_Priority_Detect_All]
        ,AntiSpyware.Low_Priority_Prevent_All AS [AntiSpyware Low_Priority_Prevent_All]
        ,AntiSpyware.Low_Priority_Detect_All AS [AntiSpyware Low_Priority_Detect_All]
        ,AntiVirus.Enabled AS [AntiVirus Enabled]
        ,AntiVirus.Inspect_HTTP
        ,AntiVirus.Inspect_FTP
        ,AntiVirus.Inspect_IMAP
        ,AntiVirus.Inspect_SMTP
        ,AntiVirus.Inspect_POP3
        ,AntiVirus.Inspect_cifs_netbios
        ,AntiVirus.Inspect_tcp_stream
        ,GeoIP_Audit.MissingCountries
        ,IPS.Enabled AS [IPS Enabled]
        ,IPS.High_Priority_Prevent_All AS [IPS High_Priority_Prevent_All]
        ,IPS.High_Priority_Detect_All AS [IPS High_Priority_Detect_All]
        ,IPS.Medium_Priority_Prevent_All AS [IPS Medium_Priority_Prevent_All]
        ,IPS.Medium_Priority_Detect_All AS [IPS Medium_Priority_Detect_All]
        ,IPS.Low_Priority_Prevent_All AS [IPS Low_Priority_Prevent_All]
        ,IPS.Low_Priority_Detect_All AS [IPS Low_Priority_Detect_All]
        ,System.AccountName
        ,System.model
        ,System.serial_number
        ,System.firmware_version
        ,System.uptime
        ,System.SNMP
        ,System.SecurityExpiration
        ,System.LDAP_Use_TLS
        ,System.Audit_date
        ,System.AuditID
      FROM
        AntiSpyware
        INNER JOIN AntiVirus
          ON AntiSpyware.AuditID = AntiVirus.AuditID
        INNER JOIN GeoIP_Audit
          ON AntiVirus.AuditID = GeoIP_Audit.AuditID
        INNER JOIN IPS
          ON GeoIP_Audit.AuditID = IPS.AuditID
        INNER JOIN System
          ON System.AuditID = AntiSpyware.AuditID
      WHERE
        AntiSpyware.AccountName IS NOT NULL AND AntiSpyware.Audit_Date LIKE '$($Date)%' AND System.SNMP NOT like ''
    "}

else {
    $RawdataQuery = "SELECT
AntiSpyware.Enabled AS [AntiSpyware Enabled]
,AntiSpyware.High_Priority_Prevent_All AS [AntiSpyware High_Priority_Prevent_All]
,AntiSpyware.High_Priority_Detect_All AS [AntiSpyware High_Priority_Detect_All]
,AntiSpyware.Medium_Priority_Prevent_All AS [AntiSpyware Medium_Priority_Prevent_All]
,AntiSpyware.Medium_Priority_Detect_All AS [AntiSpyware Medium_Priority_Detect_All]
,AntiSpyware.Low_Priority_Prevent_All AS [AntiSpyware Low_Priority_Prevent_All]
,AntiSpyware.Low_Priority_Detect_All AS [AntiSpyware Low_Priority_Detect_All]
,AntiVirus.Enabled AS [AntiVirus Enabled]
,AntiVirus.Inspect_HTTP
,AntiVirus.Inspect_FTP
,AntiVirus.Inspect_IMAP
,AntiVirus.Inspect_SMTP
,AntiVirus.Inspect_POP3
,AntiVirus.Inspect_cifs_netbios
,AntiVirus.Inspect_tcp_stream
,GeoIP_Audit.MissingCountries
,IPS.Enabled AS [IPS Enabled]
,IPS.High_Priority_Prevent_All AS [IPS High_Priority_Prevent_All]
,IPS.High_Priority_Detect_All AS [IPS High_Priority_Detect_All]
,IPS.Medium_Priority_Prevent_All AS [IPS Medium_Priority_Prevent_All]
,IPS.Medium_Priority_Detect_All AS [IPS Medium_Priority_Detect_All]
,IPS.Low_Priority_Prevent_All AS [IPS Low_Priority_Prevent_All]
,IPS.Low_Priority_Detect_All AS [IPS Low_Priority_Detect_All]
,System.AccountName
,System.model
,System.serial_number
,System.firmware_version
,System.uptime
,System.SNMP
,System.SecurityExpiration
,System.LDAP_Use_TLS
,System.Audit_date
,System.AuditID
FROM
AntiSpyware
INNER JOIN AntiVirus
  ON AntiSpyware.AuditID = AntiVirus.AuditID
INNER JOIN GeoIP_Audit
  ON AntiVirus.AuditID = GeoIP_Audit.AuditID
INNER JOIN IPS
  ON GeoIP_Audit.AuditID = IPS.AuditID
INNER JOIN System
  ON System.AuditID = AntiSpyware.AuditID
WHERE
AntiSpyware.AccountName IS NOT NULL
"}
    $Rawdata = Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $RawdataQuery

    foreach ($i in $Rawdata) {
 


        $AS = [PSCustomObject]@{
            Enabled                     = $i.'AntiSpyware Enabled'
            High_Priority_Prevent_All   = $i.'AntiSpyware High_Priority_Prevent_All'
            High_Priority_Detect_All    = $i.'AntiSpyware High_Priority_Detect_All'
            Medium_Priority_Prevent_All = $i.'AntiSpyware Medium_Priority_Prevent_All'
            Medium_Priority_Detect_All  = $i.'AntiSpyware Medium_Priority_Detect_All'
            Low_Priority_Prevent_All    = $i.'AntiSpyware Low_Priority_Prevent_All'
            Low_Priority_Detect_All     = $i.'AntiSpyware Low_Priority_Detect_All'
        }
       

        $AV = [PSCustomObject]@{
            Enabled              = $i.'AntiVirus Enabled'
            Inspect_HTTP         = $i.Inspect_HTTP
            Inspect_FTP          = $i.Inspect_FTP
            Inspect_IMAP         = $i.Inspect_IMAP
            Inspect_SMTP         = $i.Inspect_SMTP
            Inspect_POP3         = $i.Inspect_POP3
            Inspect_cifs_netbios = $i.Inspect_cifs_netbios
            Inspect_tcp_stream   = $i.Inspect_tcp_stream
        }

        $IPS = [PSCustomObject]@{
            Enabled                     = $i.'IPS Enabled'
            High_Priority_Prevent_All   = $i.'IPS High_Priority_Prevent_All'
            High_Priority_Detect_All    = $i.'IPS High_Priority_Detect_All'
            Medium_Priority_Prevent_All = $i.'IPS Medium_Priority_Prevent_All'
            Medium_Priority_Detect_All  = $i.'IPS Medium_Priority_Detect_All'
            Low_Priority_Prevent_All    = $i.'IPS Low_Priority_Prevent_All'
            Low_Priority_Detect_All     = $i.'IPS Low_Priority_Detect_All'
        }

        $Audit = [PSCustomObject]@{
            AccountName        = $i.AccountName
            model              = $i.model
            serial_number      = $i.serial_number
            firmware_version   = $i.firmware_version
            uptime             = $i.uptime
            SNMP               = $i.SNMP
            SecurityExpiration = $i.SecurityExpiration
            LDAP_Use_TLS       = $i.LDAP_Use_TLS
            Audit_date         = ($i.audit_date.tostring() -split (" "))[0]
            AuditID            = $i.AuditID
            AntiVirus          = if ($NUll -eq ($av.psobject.properties | Where-Object { $_.value -match "False" })) { "All Required Options Enabled" } else { ($Av.psobject.properties | Where-Object { $_.value -match "False" }).name }
            AntiSpyware        = if ($Null -eq ($as.psobject.properties | Where-Object { $_.value -match "False" -and $_.Name -ne "Low_Priority_Prevent_All" })) { "All Required Options Enabled" } else { ($as.psobject.properties | Where-Object { $_.value -match "False" -and $_.Name -ne "Low_Priority_Prevent_All" }).name }
            GeoIP              = [System.Collections.ArrayList]@()
            IPS                = if ($NUll -eq ($ips.psobject.properties | Where-Object { $_.value -match "False" -and $_.name -ne "Low_Priority_Prevent_All" })) { "All Required Options Enabled" } else { ($ips.psobject.properties | Where-Object { $_.value -match "False" -and $_.name -ne "Low_Priority_Prevent_All" }).name }
        }
        foreach ($Country in $i.MissingCountries) {
            if ($Country | where-object { $_ -match "'" }) { 
                $country = $country.replace("'", "''") 
            }
            [System.Collections.ArrayList]$Audit.GeoIP += $Country
        }
        $ReportQuery = "
            INSERT INTO [dbo].[Report_Table]
                    ([AuditID]
                    ,[AccountName]
                    ,[Model]
                    ,[Firmware]
                    ,[SerialNumber]
                    ,[SNMP]
                    ,[Uptime]
                    ,[SecureLDAP]
                    ,[SecurityExpiration]
                    ,[Audit_Date]
                    ,[AntiSpyware]
                    ,[AntiVirus]
                    ,[IPS]
                    ,[GeoIP_MissingCountries])
            VALUES
                    ('$($Audit.AuditID)'
                    ,'$($Audit.AccountName)'
                    ,'$($Audit.model)'
                    ,'$($Audit.firmware_version)'
                    ,'$($Audit.serial_number)'
                    ,'$($Audit.SNMP)'
                    ,'$($Audit.Uptime)'
                    ,'$($Audit.LDAP_Use_TLS)'
                    ,'$($Audit.SecurityExpiration)'
                    ,'$($Audit.Audit_date)'
                    ,'$($Audit.AntiSpyware)'
                    ,'$($Audit.AntiVirus)'
                    ,'$($Audit.IPS)'
                    ,'$($Audit.GeoIP)')
GO
"
        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $ReportQuery
      
    }
}