<#
Developed by OTORIO LTD. - www.otorio.com
Version 1.0
Licensed under GPL V3
#>

 param (
    [Parameter(Mandatory=$false)][Switch]$Disable = $false,
    [Parameter(Mandatory=$false)][Switch]$Enable = $false,
    [Parameter(Mandatory=$false)][Switch]$Raise = $false,
    [Parameter(Mandatory=$false)][Switch]$Lower = $false,
    [Parameter(Mandatory=$false)][Switch]$Help = $false
 )

$KeyPath = "HKLM:\SOFTWARE\Microsoft\Ole\AppCompat"
$RequiresubKey ="RequireIntegrityActivationAuthenticationLevel"
$RaisesubKey = "RaiseActivationAuthenticationLevel"
$RaiseValue = 2
$LowerValue = 1
$valueDisable = 0
$valueEnable = 1
$notSetWell = $false
$global:isAdmin = $true

function set_registry_key{
    Param(
    [Parameter(Mandatory=$true)]
    [string]$path,
    [Parameter(Mandatory=$true)]
    [string]$key,
    [Parameter(Mandatory=$true)]
    [string]$value)
    
    if(-Not $global:isAdmin){
        return
        }
    try {
        Write-Host "Trying to change $($key) to $($value)..."
        $result = New-ItemProperty -Path $path -Name $key -Value $value -Type DWord -Force -ErrorAction Stop
        Write-Host "$($key) changed to $($value) successfully"
    }
    catch [System.Security.SecurityException] {
        $global:isAdmin = $false
        Write-Host "Insufficient permissions to change the registry value, Make sure to run as Administrator"
    }
}



if ($Help) {
    Write-Host "`nDCOM Hardening toolkit (due to KB5004442)
Usage: DisableDcomHardening.ps1 [-Disable / -Enable] [-Raise / -Lower]
	-Disable : The Hardening will be disabled
	-Enable  : The Hardening will be enabled
	-Raise   : The authentication level will be set to 2 - raise authentication level for all non-anonymous activation requests to RPC_C_AUTHN_LEVEL_PKT_INTEGRITY if it is below Packet Integrity.
	-Lower : The authentication level will be set to 1 (the default value) - default authentication level for RPC_C_AUTHN_LEVEL_PKT_INTEGRITY.`n
Notes:
	Lower and Raise flags require the Enabled flag to be set
	Running as Administrator is required for any changes to take place
	The modification is effective only until March 14, 2023
For more information:`n https://support.microsoft.com/en-us/topic/kb5004442-manage-changes-for-windows-dcom-server-security-feature-bypass-cve-2021-26414-f1400b52-c141-43d2-941e-37ed901c769c`n`n"
    Exit
}

if ($Disable -And $Enable) {
    Write-Host("Illegal input - use Enable or Disable only!")
    Exit
    }
if ($Raise -and $Lower) {
    Write-Host("Illegal input - use Raise or Lower only!")
    Exit
    }
   
Write-Host "`n##################################"
Write-Host "DCOM Hardening toolkit"
Write-Host "Created by OTORIO - www.otorio.com"
Write-Host "##################################`n"

# Getting all low Authentication DCOM applications from WMI
Write-Host "Low Authentication DCOM applications:"
Get-WmiObject -Query "SELECT * FROM Win32_DCOMApplicationSetting where AuthenticationLevel<5" | Format-Table -Property Caption, AppID, AuthenticationLevel

# Get RequireIntegrityActivationAuthenticationLevel value
try{ 
	$result = Get-ItemProperty -Path $KeyPath -Name $RequiresubKey -ErrorAction Stop
    $reg_value = $result.($RequiresubKey)
    $data_to_print = "$($RequiresubKey) value is: $($reg_value)`n"
    if ($($reg_value) -eq $valueDisable){
        $data_to_print += "Hardening is Disabled."
    }
    elseif ($($reg_value) -eq $valueEnable){
        $data_to_print += "Hardening is Enabled."
    }
    Write-Host $data_to_print
    if(($result.($RequiresubKey) -eq $valueDisable -And $Disable) -Or ($reg_value -eq $valueEnable -And $Enable)) {
        Write-Host "Value is already set for $($RequiresubKey) - no change is required"
    }
    else {$notSetWell = $true}
}  
catch {
        Write-Host "Value is not set for $($RequiresubKey)"
        $notSetWell = $true
    } 

    
if ($Disable) {
    if ($notSetWell){
    set_registry_key $KeyPath $RequiresubKey $valueDisable
    }
    Remove-ItemProperty -Path $KeyPath -Name $RaisesubKey -Force
}

if ($Enable -And $notSetWell) {
    set_registry_key $KeyPath $RequiresubKey $valueEnable
}

if ($Enable -And ($Raise -Or $Lower)){
    try{ 
	$result = Get-ItemProperty -Path $KeyPath -Name $RaisesubKey -ErrorAction Stop
    $result_value = $result.($RaisesubKey)
    $data_to_print = "$($RaisesubKey) value is: $($result_value)`n"
    if ($result_value -eq $RaiseValue){
        $data_to_print = "Activation Authentication Level is raised."
    }
    elseif ($result_value -eq $LowerValue){
        $data_to_print = "Activation Authentication Level is Default."
    }
    Write-Host $data_to_print
    if(($result_value -eq $RaiseValue -And $Raise) -or ($result_value -eq $LowerValue -And $Lower)){
        Write-Host "Value is already set for $($RaisesubKey) - no change is required"
    }
    else {$notSetWell = $true}
    }
    catch {$notSetWell = $true}
    if ($notSetWell){
        $val_to_set = if ($Raise) { $RaiseValue } else { $LowerValue }
        set_registry_key $KeyPath $RaisesubKey $val_to_set
    }
}

if (-Not $Disable -And -Not $Enable) {
    Write-Host("No flag is set - no action is taken. Use -Enable or -Disable to take action!")
    }
           