function Add-SonicwallTarget {
    param (
        
    )
 
    $AccountName = Read-Host -Prompt "Enter Account Name"
    $AccountID = Read-Host -Prompt "Enter Autotask Account ID"
    $Active = Read-Host -Prompt "Is this an active appliance? Y/N"
    $ITGlueID = Read-Host -Prompt "Enter IT Glue account iD"
    $asset = Read-host -Prompt "Enter IT Glue asset ID"
    $tfa = read-host -Prompt "Enter TFA secret if enabled"
    $MFAEnabled = read-host -Prompt "Is MFA Enabled ? Y/N"
    $Gen7 = Read-host -Prompt "Is this a Gen 7 appliance ? "  
    $AddSystemQuery = "
        INSERT INTO [accounts] 
           ([AccountName] 
           ,[AccountID] 
           ,[Active]
           ,[ITGlueID]
           ,[Asset]
           ,[tfa]
           ,[MFAEnabled]
           ,[Gen7]) 
     VALUES 
           ('$($AccountName)' 
           ,'$($AccountID)' 
           ,'$($Active)'
           ,'$($ITGlueID)'
           ,'$($Asset)'
           ,'$($tfa)'
           ,'$($MFAEnabled)'
           ,'$($Gen7)') 
GO
"
    Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query $AddSystemQuery
    Invoke-Sqlcmd -ServerInstance $instance -Database $DBName -Credential $creds -Query "SELECT * FROM Accounts WHERE AccountName='$($AccountName)'"
      
    
}