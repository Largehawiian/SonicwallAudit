# Importing public and private functions
$PSScript = "C:\Program Files\WindowsPowerShell\Modules\SonicwallAudit\0.0.1"
$PublicFunc = @(Get-ChildItem -Path $PSScript\*.ps1 -ErrorAction SilentlyContinue)


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