function Set-Connection {
    param (
        [string]$AccountName
    )
    begin {
        $AuditTarget = Get-Targets -AccountName $AccountName
        $cred = (Get-ITGluePasswords -organization_id $AuditTarget.ITGlueID -id $AuditTarget.Asset).data.attributes
        
        $connectioninfo = [PSCustomObject]@{
            PubIp    = $cred.url.trimstart('https://').split(':')[0]
            Username = $cred.username
            Password = $cred.password
            OrgName  = $cred.'organization-name'
            OrgID    = $cred.'organization-id'
            TFA      = $AuditTarget.TFA
            ITGlueID = $AuditTarget.ITGlueID
            Asset   = $AuditTarget.Asset

        }

    }
    process {
        return $connectioninfo
    }
}