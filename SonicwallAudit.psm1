# Importing public and private functions
$PSScript = "C:\Program Files\WindowsPowerShell\Modules\SonicwallAudit\0.0.1"
$PublicFunc = @(Get-ChildItem -Path $PSScript\*.ps1 -ErrorAction SilentlyContinue)
$Global:instance = "SQL\Audit"
$Global:DBName = "SonicWallAudit"
$Global:Credentials = New-Object System.Management.Automation.PsCredential(((Get-ITGluePasswords -organization_id "2426633" -id "15564490").data.attributes).username, (ConvertTo-SecureString ((Get-ITGluePasswords -organization_id "2426633" -id "15564490").data.attributes).password -AsPlainText -force ))
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
if ([System.Net.ServicePointManager]::CertificatePolicy -match "System.Net.DefaultCertPolicy") {
    add-type @"
         using System.Net;
         using System.Security.Cryptography.X509Certificates;
         public class TrustAllCertsPolicy : ICertificatePolicy {
                public bool CheckValidationResult(
                     ServicePoint srvPoint, X509Certificate certificate,
                     WebRequest request, int certificateProblem) {
                         return true;
                    }
             }
"@
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
}

# Dotsourcing files
ForEach ($import in $PublicFunc) {
    Try {
        . $import.fullname
    }
    Catch {
        Write-Error -Message "Failed to import function $($import.fullname): $_"
    }
}

# Exporting just the Public functions
Export-ModuleMember -Function $PublicFunc.BaseName