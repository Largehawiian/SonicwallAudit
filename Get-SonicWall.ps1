function Get-SonicWall {
    param (
        [string]$Endpoint,
        [array]$AuditTarget,
        [string]$Token,
        [array]$Connection
        
        
        
    )
    begin {
        $cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
        
        $Script:Connection = [PSCustomObject]@{
            PubIp    = $cred.url.trimstart('https://').split(':')[0].tostring()
            Username = $cred.username
            Password = $cred.password
            OrgName  = $cred.'organization-name'
            OrgID    = $cred.'organization-id'
            TFA      = $AuditTarget.TFA
        }

        if (!$Token -and !$ENV:SWToken) {
            $token = (Send-TFA -connection $Script:Connection)
        }
        if ($ENV:SWToken) { $token = $ENV:SWToken }
        $Script:Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $Script:Headers.Add("Authorization", $token)

        
        switch ($Endpoint) {
            "DNS"            { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/dns" -Method 'GET' -Headers $Script:Headers }
            "Config"         { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/current" -Method 'GET' -Headers $Script:Headers }
            "AccessRules"    { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/access-rules/ipv4" -Method 'GET' -Headers $Script:Headers} 
            "System"         { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/reporting/system"-Method 'GET' -Headers $Script:Headers } 
            "GAV"            { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/gateway-antivirus/settings" -Method 'GET' -Headers $Script:Headers }
            "GeoIP"          { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/geo-ip" -Method 'GET' -Headers $Script:Headers).geo_ip.block.country }
            "IPS"            { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/intrusion-prevention/global" -Method 'GET' -Headers $Script:Headers).intrusion_prevention }
            "SecExpiration"  { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/reporting/intrusion-prevention" -Method 'GET' -Headers $Script:Headers).ips_service_expiration_date }
            "BotNet"         { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/botnet/global" -Method 'GET' -Headers $Script:Headers).botnet }
            "SNMP"           { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/snmp/settings" -Method 'GET' -Headers $Script:Headers).snmp }
            "Administration" { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/administration/global" -Method 'GET' -Headers $Script:Headers).Administration }
            "AntiSpyware"    { (Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/anti-spyware/global" -Method 'GET' -Headers $Script:Headers).anti_spyware }
            "DelAuth"        { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $Script:Headers }
            "Pending"        { Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/config/pending" -Method 'GET' -Headers $Script:Headers}
        }

        if (!$Token){
        Invoke-RestMethod "https://$($Script:Connection.PubIP):2020/api/sonicos/auth" -Method 'DEL' -Headers $Script:Headers | Out-Null
        $env:SWToken = $null
        }
   
    }
}