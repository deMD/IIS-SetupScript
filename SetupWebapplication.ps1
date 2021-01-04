$TargetserverName= Read-Host -Prompt "Input database server name (eg. localhost\sqlexpress)"

######################################################################
####################### GET SITE CONFIG ##############################
######################################################################

Write-Host "Get config"
$iisconfig = Get-Content  "$PSScriptRoot\iis-config.json" | Out-String | ConvertFrom-Json

$IISWebsiteName = $iisconfig."iisWebsiteName"
$ApppoolNetVersion = $iisconfig."apppoolNetVersion"
$DatabaseName = $IISWebsiteName
$WebsiteUrl = "$IISWebsiteName".ToLower() + ".com.local"

######################################################################
####################### ADD IIS BINDING ##############################
######################################################################

Import-Module WebAdministration

Write-Host "Create Apppool"
if(!(Test-Path IIS:\AppPools\$IISWebsiteName -pathType container)){
    $AppPool = New-WebAppPool $IISWebsiteName
    $AppPool | Set-ItemProperty -Name "managedRuntimeVersion" -Value $ApppoolNetVersion
}

Write-Host "Create Website"
if(!(Get-Website -Name "$IISWebsiteName")){
    New-Website -Name $IISWebsiteName -PhysicalPath $PSScriptRoot -ApplicationPool $IISWebsiteName -HostHeader $WebsiteUrl

    if(!(Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$WebsiteUrl"})){
        New-SelfSignedCertificate -DnsName "$WebsiteUrl" -CertStoreLocation "cert:\LocalMachine\My"
    }

    New-WebBinding -Name $IISWebsiteName -Protocol "https" -Port 443 -IPAddress * -HostHeader $WebsiteUrl -SslFlags 1
    $Thumbprint = (Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object {$_.Subject -eq "CN=$WebsiteUrl"}).Thumbprint;
    $Cert = (Get-ChildItem -Path "cert:\LocalMachine\My\$Thumbprint")

    if(!(Get-ChildItem -Path Cert:\LocalMachine\Root | Where-Object {$_.Thumbprint -eq $Thumbprint})){
        $DestStore = new-object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root,"localmachine")
        $DestStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $DestStore.Add($Cert)
        $DestStore.Close()
    }
    (Get-WebBinding -Name $IISWebsiteName -Port 443 -Protocol "https" -HostHeader $WebsiteUrl).AddSslCertificate($Thumbprint, "my")
}

######################################################################
####################### UPDATE HOSTS FILE ############################
######################################################################

Write-Host "Update hostsfile"
If ((Get-Content "$($env:windir)\system32\Drivers\etc\hosts" ) -notcontains "127.0.0.1		$WebsiteUrl")  
 {ac "$($env:windir)\system32\Drivers\etc\hosts" "`n127.0.0.1		$WebsiteUrl" }

######################################################################
####################### IMPORT DATABASE ##############################
######################################################################

Write-Host "Import databse"
$RootDir = (Get-Item $PSScriptRoot).parent.parent.parent.FullName
$BackupDirectory= "$RootDir\bak"
$bacpacFile = Get-ChildItem -Path $BackupDirectory\*.bacpac | Sort-Object LastAccessTime -Descending | Select-Object -First 1
$file = "$bacpacFile";

$DropDatabaseQuery = 
@"
IF EXISTS (SELECT * FROM [sys].[databases] WHERE [name] = '$DatabaseName') DROP DATABASE [$DatabaseName]
"@

Write-Host "Drop existing"
SQLCMD -S $TargetserverName -E -Q $DropDatabaseQuery

Write-Host "Import bacpac"
SqlPackage.exe /a:IMPORT /sf:$file /tdn:$DatabaseName /tsn:$TargetServerName

Write-Host "Create user"
$CreateUserQuery =
@"
IF EXISTS (SELECT * FROM [sys].[databases] WHERE [name] = '$DatabaseName')
BEGIN
IF NOT EXISTS (SELECT * FROM [sys].[server_principals] WHERE [name] = 'IIS APPPOOL\$IISWebsiteName')
CREATE LOGIN [IIS APPPOOL\$IISWebsiteName] FROM WINDOWS WITH DEFAULT_DATABASE = [$DatabaseName]
IF NOT EXISTS (SELECT * FROM [$DatabaseName].[sys].[sysusers] WHERE [name] = 'IIS APPPOOL\$IISWebsiteName')
BEGIN
USE [$DatabaseName]
CREATE USER [IIS APPPOOL\$IISWebsiteName] FROM LOGIN [IIS APPPOOL\$IISWebsiteName]
WITH DEFAULT_SCHEMA = [dbo]
ALTER ROLE [db_owner] ADD MEMBER [IIS APPPOOL\$IISWebsiteName];
END
END
"@

Write-Host "Create user"
SQLCMD -S $TargetserverName -E -Q $CreateUserQuery

######################################################################
####################### SET FOLDER PERMISSIONS #######################
######################################################################

Write-Host "Set folder permissions"
$ACL = Get-Acl $PSScriptRoot
$Entry = "IIS APPPOOL\$IISWebsiteName","Modify","ContainerInherit,ObjectInherit","None","Allow"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($Entry)
$ACL.SetAccessRule($AccessRule)
Set-Acl -Path $PSScriptRoot -AclObject $ACL