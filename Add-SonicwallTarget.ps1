function Add-SonicwallTarget {
    param (
        
    ) 
    $Script:Account = Read-Host -Prompt "Paste Account from Autotask"
    $Script:Active = Read-Host -Prompt "Is this an active appliance? Y/N"
    $Script:ITGlue = Read-Host -Prompt "Enter IT Glue URL for this appliance"
    $Script:TFA = read-host -Prompt "Enter TFA secret if enabled"
    $Script:MFAEnabled = read-host -Prompt "Is MFA Enabled ? Y/N"
    $Script:Gen7 = Read-host -Prompt "Is this a Gen 7 appliance ? "  
    $Script:Note = Read-Host -Prompt "If this is a satellite firewall or additinal fireawll, please note here."
    
    $Script:AccountName = $Script:Account.Split("-")[-1].trim(" ")
    $Script:AccountID = $Script:Account.split(" ")[0]
    
    $Script:ITGlueID = $Script:ITGlue.Split("/")[3]
    $Script:Asset = $Script:ITGlue.Split("/")[5]

    $Script:AddSystemQuery = "
        INSERT INTO [accounts] 
           ([AccountName] 
           ,[AccountID] 
           ,[Active]
           ,[ITGlueID]
           ,[Asset]
           ,[tfa]
           ,[$Script:MFAEnabled]
           ,[Gen7]
           ,[Note]) 
     VALUES 
           ('$($Script:AccountName)' 
           ,'$($Script:AccountID)' 
           ,'$($Script:Active)'
           ,'$($Script:ITGlueID)'
           ,'$($Script:Asset)'
           ,'$($Script:TFA)'
           ,'$($Script:MFAEnabled)'
           ,'$($Script:Gen7)'
           ,'$($Script:Note)') 
GO
"
    Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentails -Query $Script:AddSystemQuery
    Invoke-Sqlcmd -ServerInstance $Global:Instance -Database $Global:DBName -Credential $Global:Credentails -Query "SELECT * FROM Accounts WHERE AccountName='$($Script:AccountName)'"
      
    
}