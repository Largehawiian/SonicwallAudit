function Start-SwAuditSQL {
    param (
        [array]$AuditTarget
    )
    begin {
        $cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
        
        $connectioninfo = [PSCustomObject]@{
            PubIp    = $cred.url.trimstart('https://').split(':')[0]
            Username = $cred.username
            Password = $cred.password
            OrgName  = $cred.'organization-name'
            OrgID    = $cred.'organization-id'
            TFA      = $AuditTarget.TFA
        }
        $instance = "SQL\SQLEXPRESS01"
        $DBName = "SonicWallAudit"

        $username = "SWAudit"
        $pass = ConvertTo-SecureString "Welcome2!" -AsPlainText -Force
        $creds = New-Object System.Management.Automation.PsCredential($username, $pass)

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
        try {
            write-host -foregroundcolor Green "Connecting to $($Connectioninfo.OrgName)"
            Connect-SWAppliance -Server $connectioninfo.PubIp -Port 2020 -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList ($connectioninfo.username, (ConvertTo-SecureString $connectioninfo.password -AsPlainText -Force)))
        }
        catch {
            write-host -foregroundcolor Red "Connection Failed"
            $ErrorMessage = "Failed to connect to SonicWALL Appliance"
            Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "INSERT INTO [ErrorTable] 
            ([AccountName]
            ,[Audit_Date]
            ,[ErrorMessage])
            VALUES
            ('$($connectioninfo.orgname)'
            ,'$($AuditDate)'
            ,'$($ErrorMessage)')
            GO "
            return "Connection Failed to $($Connectioninfo.OrgName)"
        }
        try{
            $Configuration = [PSCustomObject]@{
                System             = (Get-SWSystem)
                Administration     = (Get-SWAdministration)
                SNMP               = (Get-SWsnmp)
                Time               = (Get-SWTime)
                CFSZones           = (Get-SWcfsPolicies)
                AntiSpyware        = (Get-SWAntiSpyware)
                AntiVirus          = (Get-SWGatewayAntiVirus)
                GeoIP              = (Get-SWGeoIP)
                BotNetandLogging   = (Get-SWbotnet)
                SecurityExpiration = (Get-SWSecServicesExpiration)
                EnabledCFSPolicies = (Get-SWcfsPolicies)
                IPS                = (Get-SWIPS)
                LDAP               = (Get-SWUserSettings)
                SecurityServices   = (Get-SWSecServicesExpiration)
                MissingCountries   = [System.Collections.ArrayList]@()
            }
        }
        catch{

        }
    
        try {
            foreach ($country in $GeoIPReference.countries) {
                if ($Configuration.GeoIP.block.country | Where-Object { $_.name -match $Country } ) {               
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


