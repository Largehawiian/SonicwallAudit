function Send-TFA {
    param (
        [array]$connection
    )
  

    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tfa = [PSCustomObject]@{
        user     = $connection.Username
        password = $connection.Password
        tfa      = (Get-OTP -SECRET $connection.tfa -LENGTH "6" -WINDOW "30" )
        override = "true"
    } | ConvertTo-Json

    $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $headers.Add("Content-Type", "application/json")
    $response = Invoke-RestMethod "https://$($connection.pubip):2020/api/sonicos/tfa" -Method 'POST' -Headers $headers -Body $tfa 
    if (!$response) {
        return "No Token received "
    }
    $token = $response.replace("INFO: Success. BearToken:", "Bearer")
    $token = $token.replace("Bearer:", ("Bearer"))
    $ENV:SWToken = $token
    return $token
}