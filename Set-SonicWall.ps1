function Set-SonicWall {
    param (
        [string]$Endpoint,
        [string]$Script:Token,
        [array]$AuditTarget,
        [switch]$BasicAuth
    )
    
    $Script:Cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
    if ($debug) { $Script:Cred; Start-Sleep -Seconds 5 }
    $Script:Connection = [PSCustomObject]@{
        PubIp    = $Script:Cred.url.trimstart('https://').split(':')[0]
        Username = $Script:Cred.username
        Password = $Script:Cred.password
        OrgName  = $Script:Cred.'organization-name'
        OrgID    = $Script:Cred.'organization-id'
        TFA      = $AuditTarget.TFA
    }

    if (!$BasicAuth) {
        if (!$Script:Token -and !$ENV:SWToken) {
            $Script:Token = (Send-TFA -connection $Script:Connection)
        }
        if ($ENV:SWToken) { $Script:Token = $ENV:SWToken }
        $Script:Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $Script:Headers.Add("Authorization", $Script:Token)
   
        switch ($Endpoint) {
            "DNS"         { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/dns" -Method 'GET' -Headers $Script:Headers }
            "Config"      { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/current" -Method 'GET' -Headers $Script:Headers }
            "AccessRules" { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/access-rules/ipv4" -Method 'GET' -Headers $Script:Headers } 
            "System"      { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/reporting/system"-Method 'GET' -Headers $Script:Headers } 
            "GAV"         { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/gateway-antivirus/settings" -Method 'GET' -Headers $Script:Headers }
            "GeoIP"       {
                $Script:GeoIPReference = Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Script:Creds -Query 'SELECT * FROM GeoIP_Reference;'
                $Script:Body = @{
                    geo_ip = @{
                        block = @{
                            country = @(
                                $Script:GeoIPReference.countries | ForEach-Object { @{ name = $_ } }
                            )
                        }
                    }
                } | ConvertTo-Json -Depth 4
                $Script:Response = Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/geo-ip" -Method 'PUT' -Headers $Script:Headers -Body $Script:Body 
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' -Headers $Script:Headers
                
            }
            "IPS"           { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/intrusion-prevention/global" -Method 'GET' -Headers $Script:Headers).intrusion_prevention }
            "SecExpiration" { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/reporting/intrusion-prevention" -Method 'GET' -Headers $Script:Headers).ips_service_expiration_date }
            "BotNet"        { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/botnet/global" -Method 'GET' -Headers $Script:Headers).botnet }
            "SNMP"          { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/snmp/settings" -Method 'GET' -Headers $Script:Headers).snmp }
            "Administration"{ (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/administration/global" -Method 'GET' -Headers $Script:Headers).Administration }
            "AntiSpyware"   { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/anti-spyware/global" -Method 'GET' -Headers $Script:Headers).anti_spyware }
            "DelAuth"       { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $Script:Headers }
            "Commit"        { $Script:Response = Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' -Headers $Script:Headers }
        }
    }
    if ($BasicAuth) {
        Connect-SWAppliance -Server $Script:Connection.PubIp -Port 2020 -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList ($Script:Connection.username, (ConvertTo-SecureString $Script:Connection.password -AsPlainText -Force)))
        switch ($Endpoint) {
            "DNS"         { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/dns" -Method 'GET' -Headers $Script:Headers }
            "Config"      { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/current" -Method 'GET' -Headers $Script:Headers }
            "AccessRules" { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/access-rules/ipv4" -Method 'GET' -Headers $Script:Headers } 
            "System"      { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/reporting/system"-Method 'GET' -Headers $Script:Headers } 
            "GAV"         { 
                $Script:Body = @{
                    gateway_antivirus = @{
                        enable              = $true
                        inbound_inspection  = @{
                            http         = $true
                            ftp          = $true
                            imap         = $true
                            smtp         = $true
                            pop3         = $true
                            cifs_netbios = $true
                            tcp_stream   = $true
                        }
                        outbound_inspection = @{
                            http       = $true
                            ftp        = $true
                            smtp       = $true
                            tcp_stream = $true
                        }
                    }
                } | ConvertTo-Json -Depth 3
                
                
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/gateway-antivirus/settings" -Method 'PUT' -Body $Script:Body
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' 
            }
            "GeoIP"     {
                $Script:GeoIPReference = Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Script:Creds -Query 'SELECT * FROM GeoIP_Reference;'
                $Script:Body = @{
                    geo_ip = @{
                        block = @{
                            country = @(
                                $Script:GeoIPReference.countries | ForEach-Object { @{ name = $_ } }
                            )
                        }
                    }
                } | ConvertTo-Json -Depth 4
                $Script:Response = Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/geo-ip" -Method 'PUT' -Body $Script:Body 
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST'
                if ($Debug) { $Script:GeoIPReference; $Script:Body ; $Script:Response ; Start-Sleep -Seconds 5 }
            }
            "IPS" {
                $Script:Body = @{
                    intrusion_prevention = @{
                        enable          = $True
                        signature_group = @{
                            high_priority   = @{
                                prevent_all = $True
                                detect_all  = $True
                            }
                            medium_priority = @{
                                prevent_all = $True
                                detect_all  = $True
                            }
                            low_priority    = @{
                                prevent_all    = $False
                                detect_all     = $True
                                log_redundancy = 60
                            }
                        }
                    }
                } | Convertto-json -Depth 10
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/intrusion-prevention/global" -Method 'PUT'-Body $Script:Body 
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST'
            }
            "SecExpiration" { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/reporting/intrusion-prevention" -Method 'GET' -Headers $Script:Headers).ips_service_expiration_date }
            "BotNet"        { 
                $Script:Body = @{
                    botnet = @{
                        block       = @{
                            connections             = @{
                                all = $true
                            }
                            database_not_downloaded = $false
                        }
                        
                        logging     = $true
                        include     = @{
                            block_details = $true
                        }
                        custom_list = @{
                            enable = $false
                        }
                    }  
                } | convertto-json -Depth 3 
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/botnet/global" -Method 'PUT' -Body $Script:Body
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST'
            }
            "SNMP"           { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/snmp/settings" -Method 'GET' -Headers $Script:Headers).snmp }
            "Administration" { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/administration/global" -Method 'GET' -Headers $Script:Headers).Administration }
            "AntiSpyware"    {
                $Script:Body = @{
                    anti_spyware = @{
                        enable          = $true
                        signature_group = @{
                            high_danger   = @{
                                prevent_all    = $true
                                detect_all     = $true
                                log_redundancy = 0
                            }
                            medium_danger = @{
                                prevent_all    = $true
                                detect_all     = $true
                                log_redundancy = 0
                            }
                            low_danger    = @{
                                prevent_all    = $false
                                detect_all     = $true
                                log_redundancy = 0
                            }
                        }
                        inspection      = @{
                            inbound  = @{
                                http = $true
                                ftp  = $true
                                imap = $true
                                smtp = $true
                                pop3 = $true
                            }
                            outbound = $true
                        }
                    }
                } | ConvertTo-Json -Depth 3
                
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/anti-spyware/global" -Method 'PUT' -Body $Script:Body
                Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' 
            }
            "DelAuth"       { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $Script:Headers }
            "Commit"        { $Script:Response = Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' -Headers $Script:Headers }
        }

    }
    return $Script:Response
    Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $Script:Headers | out-null
    $env:SWToken = $null
}