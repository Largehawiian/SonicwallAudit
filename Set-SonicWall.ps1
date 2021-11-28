function Set-SonicWall {
    param (
        [string]$Endpoint,
        [string]$token,
        [array]$AuditTarget,
        [switch]$Debug,
        [switch]$BasicAuth
    )
    
    $cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
    if ($debug) { $cred; Start-Sleep -Seconds 5 }
    $connection = [PSCustomObject]@{
        PubIp    = $cred.url.trimstart('https://').split(':')[0]
        Username = $cred.username
        Password = $cred.password
        OrgName  = $cred.'organization-name'
        OrgID    = $cred.'organization-id'
        TFA      = $AuditTarget.TFA
    }
    if ($debug) { $connection; start-sleep -Seconds 5 }
    if (!$BasicAuth) {
        if (!$Token -and !$ENV:SWToken) {
            $token = (Send-TFA -connection $connection)
        }
        if ($ENV:SWToken) { $token = $ENV:SWToken }
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $token)
        if ($Debug) { $headers ; Start-Sleep -Seconds 5 }
   
        switch ($Endpoint) {
            "DNS" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/dns" -Method 'GET' -Headers $headers }
            "Config" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/current" -Method 'GET' -Headers $headers }
            "AccessRules" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/access-rules/ipv4" -Method 'GET' -Headers $headers } 
            "System" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/reporting/system"-Method 'GET' -Headers $headers } 
            "GAV" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/gateway-antivirus/settings" -Method 'GET' -Headers $headers }
            "GeoIP" {
                $GeoIPReference = Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query 'SELECT * FROM GeoIP_Reference;'
                $Body = @{
                    geo_ip = @{
                        block = @{
                            country = @(
                                $GeoIPReference.countries | ForEach-Object { @{ name = $_ } }
                            )
                        }
                    }
                } | ConvertTo-Json -Depth 4
                $response = Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/geo-ip" -Method 'PUT' -Headers $headers -Body $Body 
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' -Headers $headers
                if ($Debug) { $GeoIPReference; $body ; $response ; Start-Sleep -Seconds 5 }
            }
            "IPS" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/intrusion-prevention/global" -Method 'GET' -Headers $headers).intrusion_prevention }
            "SecExpiration" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/reporting/intrusion-prevention" -Method 'GET' -Headers $headers).ips_service_expiration_date }
            "BotNet" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/botnet/global" -Method 'GET' -Headers $headers).botnet }
            "SNMP" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/snmp/settings" -Method 'GET' -Headers $headers).snmp }
            "Administration" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/administration/global" -Method 'GET' -Headers $headers).Administration }
            "AntiSpyware" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/anti-spyware/global" -Method 'GET' -Headers $headers).anti_spyware }
            "DelAuth" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $headers }
            "Commit" { $response = Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' -Headers $headers }
        }
    }
    if ($BasicAuth) {
        Connect-SWAppliance -Server $connection.PubIp -Port 2020 -Credential (New-Object System.Management.Automation.PSCredential -ArgumentList ($connection.username, (ConvertTo-SecureString $connection.password -AsPlainText -Force)))
        switch ($Endpoint) {
            "DNS" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/dns" -Method 'GET' -Headers $headers }
            "Config" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/current" -Method 'GET' -Headers $headers }
            "AccessRules" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/access-rules/ipv4" -Method 'GET' -Headers $headers } 
            "System" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/reporting/system"-Method 'GET' -Headers $headers } 
            "GAV" { 
                $Body = @{
                    gateway_antivirus=@{
                        enable=$true
                        inbound_inspection=@{
                            http=$true
                            ftp=$true
                            imap=$true
                            smtp=$true
                            pop3=$true
                            cifs_netbios=$true
                            tcp_stream=$true
                        }
                        outbound_inspection=@{
                            http=$true
                            ftp=$true
                            smtp=$true
                            tcp_stream=$true
                        }
                    }
                } | ConvertTo-Json -Depth 3
                
                
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/gateway-antivirus/settings" -Method 'PUT' -Body $Body
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' }
            "GeoIP" {
                $GeoIPReference = Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query 'SELECT * FROM GeoIP_Reference;'
                $Body = @{
                    geo_ip = @{
                        block = @{
                            country = @(
                                $GeoIPReference.countries | ForEach-Object { @{ name = $_ } }
                            )
                        }
                    }
                } | ConvertTo-Json -Depth 4
                $response = Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/geo-ip" -Method 'PUT' -Body $Body 
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST'
                if ($Debug) { $GeoIPReference; $body ; $response ; Start-Sleep -Seconds 5 }
            }
            "IPS" {  $Body = @{
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
               Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/intrusion-prevention/global" -Method 'PUT'-Body $Body 
               Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST'}
            "SecExpiration" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/reporting/intrusion-prevention" -Method 'GET' -Headers $headers).ips_service_expiration_date }
            "BotNet" { 
                $body = @{
                    botnet=@{
                        block = @{
                        connections=@{
                            all=$true
                        }
                        database_not_downloaded=$false
                    }
                        
                    logging = $true
                    include = @{
                        block_details = $true
                    }
                    custom_list = @{
                        enable = $false
                    }
                 }  
                } | convertto-json -Depth 3 
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/botnet/global" -Method 'PUT' -Body $Body
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST'}
            "SNMP" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/snmp/settings" -Method 'GET' -Headers $headers).snmp }
            "Administration" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/administration/global" -Method 'GET' -Headers $headers).Administration }
            "AntiSpyware" {
                $body = @{
                    anti_spyware = @{
                        enable=$true
                        signature_group=@{
                            high_danger=@{
                                prevent_all=$true
                                detect_all=$true
                                log_redundancy=0
                            }
                            medium_danger=@{
                                prevent_all=$true
                                detect_all=$true
                                log_redundancy=0
                            }
                            low_danger=@{
                                prevent_all=$false
                                detect_all=$true
                                log_redundancy=0
                            }
                        }
                        inspection=@{
                            inbound=@{
                                http=$true
                                ftp=$true
                                imap=$true
                                smtp=$true
                                pop3=$true
                            }
                            outbound=$true
                        }
                    }
                } | ConvertTo-Json -Depth 3
                
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/anti-spyware/global" -Method 'PUT' -Body $Body
                Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' }
            "DelAuth" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $headers }
            "Commit" { $response = Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'POST' -Headers $headers }
        }

    }
    return $response
    Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $headers | out-null
    $env:SWToken = $null
}