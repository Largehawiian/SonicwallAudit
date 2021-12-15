function Set-Connection {
    param (
        [string]$AccountName
    )
    begin {
        $Script:AuditTarget = Get-Targets -AccountName $AccountName
        $Script:Cred = (Get-ITGluePasswords -organization_id $Script:AuditTarget.ITGlueID -id $Script:AuditTarget.Asset).data.attributes
        
        $Script:Connnectioninfo = [PSCustomObject]@{
            PubIp    = $Script:Cred.url.trimstart('https://').split(':')[0]
            Username = $Script:Cred.username
            Password = $Script:Cred.password
            OrgName  = $Script:Cred.'organization-name'
            OrgID    = $Script:Cred.'organization-id'
            TFA      = $Script:AuditTarget.TFA
            ITGlueID = $Script:AuditTarget.ITGlueID
            Asset   =  $Script:AuditTarget.Asset

        }

    }
    process {
        return $Script:Connnectioninfo
    }
}