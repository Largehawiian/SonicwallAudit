function Start-SwAuditMFA {
    param (
        [array]$AuditTarget
    )
    begin {

        do {
            $Script:Cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
        }
        while ($null -eq $Script:Cred)
        
        Start-Sleep -Seconds 2
        $Script:ConnectionInfo = [PSCustomObject]@{
            PubIp    = $Script:Cred.url.trimstart('https://').split(':')[0]
            Username = $Script:Cred.username
            Password = $Script:Cred.password
            OrgName  = $Script:Cred.'organization-name'
            OrgID    = $Script:Cred.'organization-id'
            TFA      = $AuditTarget.TFA
        }
        If ($NUll -eq $Script:ConnectionInfo.PubIp) { Write-host "No Connection Info Generated"; exit }
    }
    process {
 
        $Script:AuditID = Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query 'SELECT TOP 1 AuditID FROM Audit_Table ORDER BY AuditID DESC;'; $Script:AuditID.Auditid++
        $Script:AuditDate = (get-date -format MM/dd/yyyy)
        $Script:GeoIPReference = Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query 'SELECT * FROM GeoIP_Reference;'
        $Script:Token = (Send-TFA -connection $Script:ConnectionInfo)
        try {
            Write-host -ForegroundColor Green "Connecting to $($Script:ConnectionInfo.orgname)"
            $Script:Configuration = [PSCustomObject]@{
                System             = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "System" )
                Administration     = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "Administration")
                SNMP               = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "SNMP")
                Time               = ""
                CFSZones           = ""
                AntiSpyware        = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "AntiSpyware")
                AntiVirus          = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "GAV")
                GeoIP              = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "GeoIP" )
                BotNetandLogging   = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "BotNet")
                EnabledCFSPolicies = ""
                IPS                = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "IPS" )
                LDAP               = ""
                SecurityServices   = (Get-Sonicwall -AuditTarget $AuditTarget -Token $Script:Token -Endpoint "SecExpiration" )
                MissingCountries   = [System.Collections.ArrayList]@()
            }
        }
        
        catch {
                Write-host -ForegroundColor Red "Failed Connecting to $($Script:ConnectionInfo.orgname)"
            $Script:ErrorMessage = "Failed Connecting to $($Script:ConnectionInfo.orgname)."
            Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query "INSERT INTO [ErrorTable] 
            ([AccountName]
            ,[Audit_Date]
            ,[ErrorMessage])
            VALUES
            ('$($Script:ConnectionInfo.orgname)'
            ,'$($Script:AuditDate)'
            ,'$($Script:ErrorMessage)')
            GO "
            return $Script:ErrorMessage
        }
        (Get-Sonicwall -AuditTarget $AuditTarget -Endpoint "DelAuth" -Token $Script:Token).Status
        $env:SWToken = $null
        $Script:Token = $null
        try {
            foreach ($country in $Script:GeoIPReference.countries) {
                if ($Script:Configuration.GeoIP | Where-Object { $_.name -match $Country } ) {               
                }
                else {
                    if ($country | where-object { $_ -match "'" }) { $country = $country.replace("'", "''") }
                    [System.Collections.ArrayList]$Script:Configuration.MissingCountries += $Country
                }
            }

        }
        catch {
            $Script:ErrorMessage = "Errors getting GeoIP Data."
            Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query "INSERT INTO [ErrorTable] 
            ([AccountName]
            ,[Audit_Date]
            ,[ErrorMessage])
            VALUES
            ('$($Script:ConnectionInfo.orgname)'
            ,'$($Script:AuditDate)'
            ,'$($Script:ErrorMessage)')
            GO "

        }
       
        

        # Queries
        $Script:AuditQuery = "INSERT INTO [Audit_Table]
        ([AccountName]
        ,[AuditID]
        ,[Audit_Date])
    VALUES 
        ('$($Script:ConnectionInfo.OrgName)'
         ,'$($Script:AuditID.AuditID)'
         ,'$($Script:AuditDate)')
GO
"

        $Script:SystemQuery = "
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
            ,'$($Script:Configuration.System.model)'
            ,'$($Script:Configuration.System.serial_number)'
            ,'$($Script:Configuration.System.firmware_version)'
            ,'$($Script:Configuration.System.up_time)'
            ,'$($Script:Configuration.snmp.get_community_name)'
            ,'$(($Script:Configuration.SecurityServices.split(" ")[0]))'
            ,'$($Script:Configuration.user.LDAP.user.ldap.server.use_tls)'
            ,'$($Script:AuditDate)'
            ,'$($Script:AuditID.AuditID)'
            )
GO
"
        $Script:AntiSpywareQuery = "
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
            ('$($Script:ConnectionInfo.OrgName)'
             ,'$($Script:Configuration.AntiSpyware.enable)'
             ,'$($Script:Configuration.AntiSpyware.signature_group.high_danger.prevent_all)'
             ,'$($Script:Configuration.AntiSpyware.signature_group.high_danger.detect_all)'
             ,'$($Script:Configuration.AntiSpyware.signature_group.medium_danger.prevent_all)'
             ,'$($Script:Configuration.AntiSpyware.signature_group.medium_danger.detect_all)'
             ,'$($Script:Configuration.AntiSpyware.signature_group.low_danger.prevent_all)'
             ,'$($Script:Configuration.AntiSpyware.signature_group.low_danger.detect_all)'
             ,'$($Script:AuditDate)'
             ,'$($Script:AuditID.AuditID)'
           )
GO
"  

        $Script:AntiVirusQuery = "
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
             ('$($Script:ConnectionInfo.OrgName)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.enable)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.http)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.ftp)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.imap)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.smtp)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.pop3)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.cifs_netbios)'
             ,'$($Script:Configuration.AntiVirus.gateway_antivirus.inbound_inspection.tcp_stream)'
             ,'$($Script:AuditDate)'
             ,'$($Script:AuditID.AuditID)')
GO
"  
        $Script:IPSQuery = "
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
            ('$($Script:ConnectionInfo.OrgName)'
             ,'$($Script:Configuration.IPS.enable)'
             ,'$($Script:Configuration.IPS.signature_group.high_priority.prevent_all)'
             ,'$($Script:Configuration.IPS.signature_group.high_priority.detect_all)'
             ,'$($Script:Configuration.IPS.signature_group.medium_priority.prevent_all)'
             ,'$($Script:Configuration.IPS.signature_group.medium_priority.detect_all)'
             ,'$($Script:Configuration.IPS.signature_group.low_priority.prevent_all)'
             ,'$($Script:Configuration.IPS.signature_group.low_priority.detect_all)'
             ,'$($Script:AuditDate)'
             ,'$($Script:AuditID.AuditID)')
GO      
"
        $Script:GeoIPQuery = "
INSERT INTO [dbo].[GeoIP_Audit]
            ([AccountName]
            ,[AuditID]
            ,[Audit_Date]
            ,[MissingCountries])
    VALUES
            ('$($Script:ConnectionInfo.OrgName)'
            ,'$($Script:AuditID.AuditID)'
            ,'$($Script:AuditDate)'
            ,'$($Script:Configuration.MissingCountries)')
GO
"

        $Script:Queries = @{
            Audit       = $Script:AuditQuery
            System      = $Script:SystemQuery
            AntiSpyware = $Script:AntiSpywareQuery
            AntiVirus   = $Script:AntiVirusQuery
            IPS         = $Script:IPSQuery
            GeoIP       = $Script:GeoIPQuery
        }



        Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query $Script:Queries.Audit
        Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query $Script:Queries.System
        Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query $Script:Queries.AntiSpyware
        Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query $Script:Queries.AntiVirus
        Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query $Script:Queries.IPS
        Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentials -Query $Script:Queries.GeoIP


  
    }
}