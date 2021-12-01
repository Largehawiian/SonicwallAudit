function Convert-HexToByteArray($hexString) {
    $byteArray = $hexString -replace '^0x', '' -split "(?<=\G\w{2})(?=\w{2})" | %{ [Convert]::ToByte( $_, 16 ) }
    return $byteArray
}