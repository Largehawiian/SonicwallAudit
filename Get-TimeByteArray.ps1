function Get-TimeByteArray($WINDOW) {
    $span = (New-TimeSpan -Start (Get-Date -Year 1970 -Month 1 -Day 1 -Hour 0 -Minute 0 -Second 0) -End (Get-Date).ToUniversalTime()).TotalSeconds
    $unixTime = [Convert]::ToInt64([Math]::Floor($span/$WINDOW))
    $byteArray = [BitConverter]::GetBytes($unixTime)
    [array]::Reverse($byteArray)
    return $byteArray
}