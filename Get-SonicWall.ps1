function Get-SonicWall {
    param (
        [string]$Endpoint,
        [array]$AuditTarget,
        [string]$Token,
        [array]$connection,
        [switch]$debug
        
        
    )
    begin {
        $cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
        if ($debug) { $cred; start-sleep -seconds 5 }
        $connection = [PSCustomObject]@{
            PubIp    = $cred.url.trimstart('https://').split(':')[0].tostring()
            Username = $cred.username
            Password = $cred.password
            OrgName  = $cred.'organization-name'
            OrgID    = $cred.'organization-id'
            TFA      = $AuditTarget.TFA
        }
    
        if ($debug) { $connection; start-sleep -seconds 5 }

        if (!$Token -and !$ENV:SWToken) {
            $token = (Send-TFA -connection $connection)
        }
        if ($ENV:SWToken) { $token = $ENV:SWToken }
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", $token)

        if ($debug) { $headers; $token; start-sleep -seconds 5 }

        #$url = 
        switch ($Endpoint) {
            "DNS" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/dns" -Method 'GET' -Headers $headers }
            "Config" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/current" -Method 'GET' -Headers $headers }
            "AccessRules" {Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/access-rules/ipv4" -Method 'GET' -Headers $headers} 
            "System" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/reporting/system"-Method 'GET' -Headers $headers } 
            "GAV" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/gateway-antivirus/settings" -Method 'GET' -Headers $headers }
            "GeoIP" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/geo-ip" -Method 'GET' -Headers $headers).geo_ip.block.country }
            "IPS" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/intrusion-prevention/global" -Method 'GET' -Headers $headers).intrusion_prevention }
            "SecExpiration" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/reporting/intrusion-prevention" -Method 'GET' -Headers $headers).ips_service_expiration_date }
            "BotNet" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/botnet/global" -Method 'GET' -Headers $headers).botnet }
            "SNMP" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/snmp/settings" -Method 'GET' -Headers $headers).snmp }
            "Administration" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/administration/global" -Method 'GET' -Headers $headers).Administration }
            "AntiSpyware" { (Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/anti-spyware/global" -Method 'GET' -Headers $headers).anti_spyware }
            "DelAuth" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $headers }
            "Pending" { Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/config/pending" -Method 'GET' -Headers $headers}
        }
        if ($debug) { $url ; $Endpoint; start-sleep -Seconds 5 }
        if (!$Token){
        Invoke-RestMethod "https://$($connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $headers | Out-Null
        $env:SWToken = $null
        }
   
    }
}