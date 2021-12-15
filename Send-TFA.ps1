function Send-TFA {
    param (
        [array]$connection
    )
  
    $Script:TFA = [PSCustomObject]@{
        user     = $connection.Username
        password = $connection.Password
        tfa      = (Get-OTP -SECRET $connection.tfa -LENGTH "6" -WINDOW "30" )
        override = "true"
    } | ConvertTo-Json

    $Script:Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Script:Headers.Add("Content-Type", "application/json")
    $Script:Response = Invoke-RestMethod "https://$($connection.pubip):2020/api/sonicos/tfa" -Method 'POST' -Headers $Script:Headers -Body $Script:TFA 
    if (!$Script:Response) {
        return "No Token received "
    }
    $Script:Token = $Script:Response.replace("INFO: Success. BearToken:", "Bearer")
    $Script:Token = $Script:Token.replace("Bearer:", ("Bearer"))
    $ENV:SWToken = $Script:Token
    return $Script:Token
}