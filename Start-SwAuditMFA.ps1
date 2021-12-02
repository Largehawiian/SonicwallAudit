function Start-SwAuditMFA {
    param (
        [array]$AuditTarget
    )
    begin {

        do {
            $cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
        }
        while ($null -eq $cred)
        
        Start-Sleep -Seconds 2
        $connectioninfo = [PSCustomObject]@{
            PubIp    = $cred.url.trimstart('https://').split(':')[0]
            Username = $cred.username
            Password = $cred.password
            OrgName  = $cred.'organization-name'
            OrgID    = $cred.'organization-id'
            TFA      = $AuditTarget.TFA
        }
        If ($NUll -eq $connectioninfo.PubIp) { Write-host "No Connection Info Generated"; exit }
        $instance = "SQL\Audit"
        $DBName = "SonicWallAudit"

        $credentials = (Get-ITGluePasswords -organization_id "2426633" -id "15564490").data.attributes
        $creds = New-Object System.Management.Automation.PsCredential($credentials.username, (ConvertTo-SecureString $credentials.password -AsPlainText -force ))

        if ([System.Net.ServicePointManager]::CertificatePolicy -match "System.Net.DefaultCertPolicy") {
            add-type @"
                 using System.Net;
                 using System.Security.Cryptography.X509Certificates;
                 public class TrustAllCertsPolicy : ICertificatePolicy {
                        public bool CheckValidationResult(
                             ServicePoint srvPoint, X509Certificate certificate,
                             WebRequest request, int certificateProblem) {
                                 return true;
                            }
                     }
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }

    }
    process {
        function Invoke-SQLQueries {
            param (
                [switch]$AuditTable,
                [String]$Query
            )
            if ($AuditTable) {
                $OutputObject = Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query 'SELECT TOP 1 AuditID FROM Audit_Table ORDER BY AuditID DESC;'
                
            }
            if ($Query) {
                Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Query
            }
            return $OutputObject
        }
        $AuditID = Invoke-SQLQueries -AuditTable; $AuditID.Auditid++
        $AuditDate = (get-date -format MM/dd/yyyy)
        $GeoIPReference = Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query 'SELECT * FROM GeoIP_Reference;'
        $token = (Send-TFA -connection $connectioninfo)
        try {
            Write-host -ForegroundColor Green "Connecting to $($connectioninfo.orgname)"
            $Configuration = [PSCustomObject]@{
                System             = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "System" )
                Administration     = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "Administration")
                SNMP               = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "SNMP")
                Time               = ""
                CFSZones           = ""
                AntiSpyware        = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "AntiSpyware")
                AntiVirus          = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "GAV")
                GeoIP              = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "GeoIP" )
                BotNetandLogging   = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "BotNet")
                EnabledCFSPolicies = ""
                IPS                = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "IPS" )
                LDAP               = ""
                SecurityServices   = (Get-Sonicwall -AuditTarget $AuditTarget -Token $token -Endpoint "SecExpiration" )
                MissingCountries   = [System.Collections.ArrayList]@()
            }
        }
        
        catch {
                Write-host -ForegroundColor Red "Failed Connecting to $($connectioninfo.orgname)"
        }
        (Get-Sonicwall -AuditTarget $AuditTarget -Endpoint "DelAuth" -Token $token).Status
        $env:SWToken = $null
        $Token = $null
        try {
            foreach ($country in $GeoIPReference.countries) {
                if ($Configuration.GeoIP | Where-Object { $_.name -match $Country } ) {               
                }
                else {
                    if ($country | where-object { $_ -match "'" }) { $country = $country.replace("'", "''") }
                    [System.Collections.ArrayList]$Configuration.MissingCountries += $Country
                }
            }

        }
        catch {
            $ErrorMessage = "Errors getting GeoIP Data."
            Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "INSERT INTO [ErrorTable] 
            ([AccountName]
            ,[Audit_Date]
            ,[ErrorMessage])
            VALUES
            ('$($connectioninfo.orgname)'
            ,'$($AuditDate)'
            ,'$($ErrorMessage)')
            GO "

        }
       
        

        # Queries
        $AuditQuery = "INSERT INTO [Audit_Table]
        ([AccountName]
        ,[AuditID]
        ,[Audit_Date])
    VALUES 
        ('$($connectioninfo.OrgName)'
         ,'$($AuditID.AuditID)'
         ,'$($AuditDate)')
GO
"

        $Systemquery = "
INSERT INTO [dbo].[System]
            ([AccountName]
            ,[model]
            ,[serial_number]
            ,[firmware_version]
            ,[uptime]
            ,[SNMP]
            ,[SecurityExpiration]
            ,[LDAP_Use_TLS]
            ,[Audit_date]
            ,[AuditID])
        VALUES
            ('$($AuditTarget.AccountName)'
            ,'$($Configuration.System.model)'
            ,'$($configuration.System.serial_number)'
            ,'$($Configuration.System.firmware_version)'
            ,'$($Configuration.System.up_time)'
            ,'$($Configuration.snmp.get_community_name)'
            ,'$(($Configuration.SecurityServices.split(" ")[0]))'
            ,'$($Configuration.user.LDAP.user.ldap.server.use_tls)'
            ,'$($AuditDate)'
            ,'$($AuditID.AuditID)'
            )
GO
"
        $AntiSpywareQuery = "
INSERT INTO [dbo].[AntiSpyware]
            ([AccountName]
            ,[Enabled]
            ,[High_Priority_Prevent_All]
            ,[High_Priority_Detect_All]
            ,[Medium_Priority_Prevent_All]
            ,[Medium_Priority_Detect_all]
            ,[Low_Priority_Prevent_ALL]
            ,[Low_Priority_Detect_All]
            ,[Audit_Date]
            ,[AuditID])
    VALUES
            ('$($connectioninfo.OrgName)'
             ,'$($Configuration.AntiSpyware.enable)'
             ,'$($configuration.AntiSpyware.signature_group.high_danger.prevent_all)'
             ,'$($configuration.AntiSpyware.signature_group.high_danger.detect_all)'
             ,'$($configuration.AntiSpyware.signature_group.medium_danger.prevent_all)'
             ,'$($configuration.AntiSpyware.signature_group.medium_danger.detect_all)'
             ,'$($configuration.AntiSpyware.signature_group.low_danger.prevent_all)'
             ,'$($configuration.AntiSpyware.signature_group.low_danger.detect_all)'
             ,'$($AuditDate)'
             ,'$($AuditID.AuditID)'
           )
GO
"  

        $AntiVirusQuery = "
INSERT INTO [dbo].[AntiVirus]
            ([AccountName]
            ,[Enabled]
            ,[Inspect_HTTP]
            ,[Inspect_FTP]
            ,[Inspect_IMAP]
            ,[Inspect_SMTP]
            ,[Inspect_POP3]
            ,[Inspect_CIFS_Netbios]
            ,[Inspect_TCP_Stream]
            ,[Audit_Date]
            ,[AuditID])
    VALUES
             ('$($connectioninfo.OrgName)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.enable)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.http)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.ftp)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.imap)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.smtp)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.pop3)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.cifs_netbios)'
             ,'$($Configuration.AntiVirus.gateway_antivirus.inbound_inspection.tcp_stream)'
             ,'$($AuditDate)'
             ,'$($AuditID.AuditID)')
GO
"  
        $IPSQuery = "
INSERT INTO [dbo].[IPS]
            ([AccountName]
            ,[Enabled]
            ,[High_Priority_Prevent_All]
            ,[High_Priority_Detect_All]
            ,[Medium_Priority_Prevent_All]
            ,[Medium_Priority_Detect_All]
            ,[Low_Priority_Prevent_All]
            ,[Low_Priority_Detect_All]
            ,[Audit_Date]
            ,[AuditID])
    VALUES
            ('$($connectioninfo.OrgName)'
             ,'$($Configuration.IPS.enable)'
             ,'$($Configuration.IPS.signature_group.high_priority.prevent_all)'
             ,'$($Configuration.IPS.signature_group.high_priority.detect_all)'
             ,'$($Configuration.IPS.signature_group.medium_priority.prevent_all)'
             ,'$($Configuration.IPS.signature_group.medium_priority.detect_all)'
             ,'$($Configuration.IPS.signature_group.low_priority.prevent_all)'
             ,'$($Configuration.IPS.signature_group.low_priority.detect_all)'
             ,'$($AuditDate)'
             ,'$($AuditID.AuditID)')
GO      
"
        $GeoIPQuery = "
INSERT INTO [dbo].[GeoIP_Audit]
            ([AccountName]
            ,[AuditID]
            ,[Audit_Date]
            ,[MissingCountries])
    VALUES
            ('$($connectioninfo.OrgName)'
            ,'$($AuditID.AuditID)'
            ,'$($AuditDate)'
            ,'$($Configuration.MissingCountries)')
GO
"

        $Queries = @{
            Audit       = $AuditQuery
            System      = $SystemQuery
            AntiSpyware = $AntiSpywareQuery
            AntiVirus   = $AntiVirusQuery
            IPS         = $IPSQuery
            GeoIP       = $GeoIPQuery
        }



        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Queries.Audit
        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Queries.System
        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Queries.AntiSpyware
        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Queries.AntiVirus
        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Queries.IPS
        Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $Queries.GeoIP


  
    }
}