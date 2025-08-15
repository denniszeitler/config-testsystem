# Configure Win Server Testsystem
# Author: @denniszeitler
# Version: v.0.3
# Description: Setup a Test System on a Windows Server:
# Components: - Powershell Modules
#             - AD-DS Role
#             - Domain Controller (with some Objects)
#             - VS Code
#             - Powershell Universal
#
# --- Do-Not-Change Variables --- #
$repo = Get-PSRepository -Name 'PSGallery';
# --- Start Module Installation --- #
#
if(-not(Get-PackageProvider -Name NuGet -ErrorAction SilentlyContinue))
{
    Write-Host "Starting NuGet-PackageProvider Installation...";
    Install-PackageProvider NuGet -Force;
}else
{
    Write-Host "NuGet-PackageProvider already installed";
}
#
if($repo.InstallPolicy -ne 'Trusted')
{
    Write-Host "Setting PSGallery -> 'Trusted...'";
    Set-PSRepository PSGallery -InstallationPolicy Trusted;
}else
{
    Write-Host "PS Gallery already 'Trusted'";
}
#
if (-not (Get-Module -ListAvailable -Name PSLogging)) {
    Write-Host "Starting Installation: PSLogging Modul...";
    Install-Module -Name PSLogging -Force;
} else {
    Write-Host "PSLogging Modul already installed.";
}
#
if (-not (Get-Module -ListAvailable -Name PSWindowsUpdate)) {
    Write-Host "Starting Installation: PSWindowsUpdate Modul...";
    Install-Module -Name PSWindowsUpdate -Force;
} else {
    Write-Host "PSWindowsUpdate Modul already installed.";
}
#
if (-not (Get-Module -ListAvailable -Name Choco)) {
    Write-Host "Installiere Choco Modul...";
    Install-Module -Name Choco -Force;
} else {
    Write-Host "Choco Modul ist bereits installiert.";
}
#
# --- END Module Installation --- #
#
# - Configuration-Variables - #
$Computername = 'DC01';
$DomainName = 'TESTSYSTEM';
$safeModeAdminPW = 'TestSystemSecurePW1!'
$ScriptPath = 'C:\Configure-Testsystem\';
$LogPath = $ScriptPath + 'Configure-Testsystem.log';
#
If(-not(Test-Path $ScriptPath))
{
    New-Item -Path "C:\" -Name "Configure-Testsystem" -ItemType "Directory" -Force;
}
#
#
if(-not(Test-Path $LogPath))
{
    Start-Log -LogPath $ScriptPath -LogName 'Configure-Testsystem.log' -ScriptVersion '1' -ErrorAction Stop;
}
else
{
    Write-LogInfo -LogPath $LogPath -Message "---> Start Script: Log File already exists. Run Script again (after reboot)." -TimeStamp;
}
#
If($env:Computername -notlike $Computername)
{
    Write-LogInfo -LogPath $LogPath  -Message ('Renaming Computer to: ' + $Computername + " ...") -TimeStamp;
    Rename-Computer -ComputerName $env:Computername -NewName $Computername;
    Write-LogInfo -LogPath $LogPath  -Message "Exit Script: Reboot required." -TimeStamp;
    Restart-Computer;
}
# --- Windows Updates --- #
# Note: Loop Get-WuInstall? 
Write-LogInfo -LogPath $LogPath  -Message 'Starting Windows Update Installation...' -TimeStamp;
Get-WUInstall -Install -AcceptAll -IgnoreReboot | Out-String | ForEach-Object{Write-LogInfo -LogPath $LogPath -Message $_};
Write-LogInfo -LogPath $LogPath  -Message 'Windows Update Installaltion finished' -TimeStamp;
#
#
if(-not(Get-WindowsFeature -Name 'AD-Domain-Services'))
{
Write-LogInfo -LogPath $LogPath  -Message 'Starting AD-DS Role Installation...' -TimeStamp;
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools;
Write-LogInfo -LogPath $LogPath  -Message 'AD-DS Role Installation finished' -TimeStamp;
}
else
{
    Write-LogInfo -LogPath $LogPath  -Message 'AD-DS Role Installation already installed' -TimeStamp;
}
#
#
if((Get-ADDomain).Name -ne $DomainName)
{
Write-LogInfo -LogPath $LogPath  -Message 'Starting Domain Controller Installation...' -TimeStamp;
Install-ADDSForest `
    -DomainName ($DomainName + ".local") `
    -DomainNetbiosName $DomainName `
    -SafeModeAdministratorPassword (ConvertTo-SecureString $safeModeAdminPW -AsPlainText -Force) `
    -InstallDNS `
    -Force
Write-LogInfo -LogPath $LogPath  -Message 'Domain Controller Installation finished' -TimeStamp;
Write-LogInfo -LogPath $LogPath  -Message "Exit Script: Reboot required." -TimeStamp;
}
else
{
    Write-LogInfo -LogPath $LogPath  -Message 'Domain Controller already installed' -TimeStamp;
}
#
# DNS-Forwarding
if(-not (Get-DnsServerForwarder))
{
    Write-LogInfo -LogPath $LogPath -Message "No DNS Forwarder found – adding Google & Cloudflare..." -TimeStamp;
    Set-DnsServerForwarder -IPAddress 8.8.8.8,1.1.1.1 -PassThru;
}
else
{
    Write-LogInfo -LogPath $LogPath -Message "DNS Forwarder already configured." -TimeStamp;
}
#
# Create OUs
$DN = (Get-ADDomain).DistinguishedName;
$ServicesOU = Get-ADOrganizationalUnit -Filter 'Name -like "Services"';

If(-not($ServicesOU))
{
    Write-LogInfo -LogPath $LogPath  -Message "Creating OU: Services" -TimeStamp;
    New-ADOrganizationalUnit -Name 'Services' -Path $DN;
    $ServicesOU = Get-ADOrganizationalUnit -Filter 'Name -like "Services"';
    #
    Write-LogInfo -LogPath $LogPath  -Message "Creating OU: Services\Test-Service" -TimeStamp;
    New-ADOrganizationalUnit -Name 'Test-Service' -Path $ServicesOU.DistinguishedName;
    $TestServiceOU = Get-ADOrganizationalUnit -Filter 'Name -like "Test-Service"' -SearchBase $ServicesOU.DistinguishedName;
    #
    Write-LogInfo -LogPath $LogPath  -Message "Creating OU: Services\Test-Service\Computers" -TimeStamp;
    New-ADOrganizationalUnit -Name 'Computers' -Path $TestServiceOU.DistinguishedName;
    New-ADComputer -Name 'ApplicationServer01' -Path ("OU=Computers," + $TestServiceOU.DistinguishedName);
    New-ADComputer -Name 'DatabaseServer01' -Path ("OU=Computers," + $TestServiceOU.DistinguishedName);
    #
    Write-LogInfo -LogPath $LogPath  -Message "Creating OU: Services\Test-Service\Users" -TimeStamp;
    New-ADOrganizationalUnit -Name 'Users' -Path $TestServiceOU.DistinguishedName;
    New-ADUser -Name 'ServiceUser01' -Path ("OU=Users," + $TestServiceOU.DistinguishedName) -Enabled $true -AccountPassword (ConvertTo-SecureString 'TestSystemPassword01!' -AsPlainText -Force);
    #
    Write-LogInfo -LogPath $LogPath  -Message "Creating OU: Services\Test-Service\Groups" -TimeStamp;
    New-ADOrganizationalUnit -Name 'Groups' -Path $TestServiceOU.DistinguishedName;
    New-ADGroup -Name 'Group01' -Path ("OU=Groups," + $TestServiceOU.DistinguishedName) -GroupScope DomainLocal
    Add-ADGroupMember -Identity 'Group01' -Members 'ServiceUser01';
    #
    Write-LogInfo -LogPath $LogPath  -Message "Services OU + Test-Service created" -TimeStamp;
}
#
# Software Installation
$chocoCommand = get-command choco.exe -ErrorAction SilentlyContinue;

if($null -eq $chocoCommand)
{
    Write-LogInfo -LogPath $LogPath -Message "Chocolatey not installed. Starting Installation." -TimeStamp;
    Install-Choco;
    Write-LogInfo -LogPath $LogPath -Message "Restarting System." -TimeStamp;
    Restart-Computer;
}
else
{
    Write-LogInfo -LogPath $LogPath -Message "Chocolatey already installed." -TimeStamp;
}
#
# Choco Packages
$chocoPackages = @("microsoft-edge","vscode","powershelluniversal");

ForEach($Package in $chocoPackages)
{

$packageInstalled = choco list --localonly | Select-String "^$Package ";
    
    if (-not $packageInstalled)
    {
        Write-LogInfo -LogPath $LogPath -Message "Package Installation: $Package" -TimeStamp;
        choco install $Package -y;
    }
    else{
        Write-LogInfo -LogPath $LogPath -Message "Package: $Package already installed." -TimeStamp;
    }
}

#Start Powershell Universal in Edge
Start-Process "msedge.exe" "http://localhost:5000/"