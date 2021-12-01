function Get-Otp($SECRET, $LENGTH, $WINDOW){
    $enc = [System.Text.Encoding]::UTF8
    $hmac = New-Object -TypeName System.Security.Cryptography.HMACSHA1
    $hmac.key = Convert-HexToByteArray(Convert-Base32ToHex(($SECRET.ToUpper())))
    $timeBytes = Get-TimeByteArray $WINDOW
    $randHash = $hmac.ComputeHash($timeBytes)
    
    $offset = $randhash[($randHash.Length-1)] -band 0xf
    $fullOTP = ($randhash[$offset] -band 0x7f) * [math]::pow(2, 24)
    $fullOTP += ($randHash[$offset + 1] -band 0xff) * [math]::pow(2, 16)
    $fullOTP += ($randHash[$offset + 2] -band 0xff) * [math]::pow(2, 8)
    $fullOTP += ($randHash[$offset + 3] -band 0xff)

    $modNumber = [math]::pow(10, $LENGTH)
    $otp = $fullOTP % $modNumber
    $otp = $otp.ToString("0" * $LENGTH)
    return $otp
}