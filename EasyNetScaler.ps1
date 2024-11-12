<#
.SYNOPSIS
	Create a backup of your NetScaler. Perform an Upgrade of your NetScaler. Clean the filesystem of your NetScaler.
.DESCRIPTION
	This script has several options to backup, clean and upgrade your NetScaler. If no commandline options are given or you just run the script through the right click menu in explorer, the script will show a GUI.
.PARAMETER Help
	Display the detailed information about this script
.PARAMETER Username
	NetScaler Username with enough access
.PARAMETER Password
	NetScaler Username password
.PARAMETER IP
	Management IP (NSIP), used to connect to the ADC
.PARAMETER Backup
	Create a Full Backup
.PARAMETER ConfigOnly
	Create a Backup from the ns.conf
.PARAMETER FirmwareFile
	The path to the firmware file
.PARAMETER Failovertime
	The date and time that the failover should occur. A Scheduled task will be created that will run at the planned time.
.EXAMPLE
	.\EasyNetScaler.ps1
	Open the GUI
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1
	Display GUI with prefilled values
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup
	Create a full backup
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Config
	Create a ns.conf backup
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Clean
	Cleanup the NetScaler filesystem
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Firmware C:\Temp\Build-14.1-12.35_nc_64.tgz
	Upgrade the NetScaler with the firmware
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Failovertime "1-2-2025 18:00"
	Plan forced failover
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup -Clean -Firmware C:\Temp\Build-14.1-12.35_nc_64.tgz -Failovertime "1-2-2025 18:00"
	Backup, Clean the FileSystem and upgrade the NetScaler with the firmware and plan the force failover
.NOTES
	File name	:	EasyNetScaler.ps1
	Version		:	1.4
	Author		:	Harm Peter Millaard
	Requires	:	PowerShell v5.1 and up
					ADC 12.1 and higher
					Internet Connection to download putty and pscp
.LINK
	https://github.com/hpmillaard/EasyNetScaler
#>

param(
	[ValidateNotNullOrEmpty()]
	[string]$Username,
	[ValidateNotNullOrEmpty()]
	[string]$Password,
	[ValidateNotNullOrEmpty()]
	[string]$IP,
	[switch]$Backup,
	[switch]$Config,
	[switch]$Clean,
	[string]$Firmware,
	[datetime]$Failovertime
)

$ptxt = "$PSScriptRoot\putty.txt"
$plog = "$PSScriptRoot\putty.log"
$putty = "$PSScriptRoot\putty.exe"
$pscp = "$PSScriptRoot\pscp.exe"

del $ptxt, $plog -EA 0

[System.Net.ServicePointManager]::CheckCertificateRevocationList={$false}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12

Add-Type -AN System.Windows.Forms
Add-Type -AN System.Drawing
function msgbox($Text){$r=[System.Windows.Forms.MessageBox]::Show($Text, $Text, [System.Windows.Forms.MessageBoxButtons]::OK)}

function New-Label($Label, $X, $Y, $Width, $Height, $FontSize, $FontStyle){
	$LabelControl = New-Object System.Windows.Forms.Label
	$LabelControl.Location = New-Object System.Drawing.Point $X, $Y
	$LabelControl.Size = New-Object System.Drawing.Size $Width, $Height
	$LabelControl.Text = $Label
	$LabelControl.Font = New-Object System.Drawing.Font("Arial",$FontSize,[System.Drawing.FontStyle]::$FontStyle)
	$Form.Controls.Add($LabelControl)
}
function New-TextBox($X, $Y, $Width, $Height){
	$TB = New-Object System.Windows.Forms.TextBox
	$TB.Location = New-Object System.Drawing.Point $X, $Y
	$TB.Size = New-Object System.Drawing.Size $Width, $Height
	$Form.Controls.Add($TB)
	return $TB
}
function New-Button($Text, $X, $Y, $Width, $Height){
	$Button = New-Object System.Windows.Forms.Button
	$Button.Location = New-Object System.Drawing.Point $X, $Y
	$Button.Size = New-Object System.Drawing.Size $Width, $Height
	$Button.Text = $Text
	$Form.Controls.Add($Button)
	return $Button
}
function New-RadioButton($Text, $X, $Y, $Width, $Height, $Checked){
	$RadioButton = New-Object System.Windows.Forms.RadioButton
	$RadioButton.Location = New-Object System.Drawing.Point $X, $Y
	$RadioButton.Size = New-Object System.Drawing.Size $Width, $Height
	$RadioButton.Text = $Text
	$RadioButton.Checked = $Checked
	$Form.Controls.Add($RadioButton)
	return $RadioButton
}

function Check{
	param($U,$P,$IP)
	If ([string]::IsNullOrEmpty($U)){msgbox "Username can't be empty";return $false}
	If ([string]::IsNullOrEmpty($P)){msgbox "Password can't be empty";return $false}
	If ([string]::IsNullOrEmpty($IP)){msgbox "IP can't be empty";return $false}
	try {
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$tcpClient.Connect($IP, 22)
		if ($tcpClient.Connected) {
			$tcpClient.Close()
			If (!(Test-Path $putty)){Start-BitsTransfer 'https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe' $putty}
			If (!(Test-Path $pscp)){Start-BitsTransfer 'https://the.earth.li/~sgtatham/putty/latest/w32/pscp.exe' $pscp}
			return $true
		} else {
			Write-Host "Unable to connect to $IP through SSH" -F Red
		}
	} catch {
		Write-Host "Unable to connect to $IP through SSH" -F Red
	}
	return $false
}

Function Backup-NS{
	param($U,$P,$IP)
	If (Check -U $U -P $P -IP $IP){
		$timestamp = Get-Date -Format yyyy_MM_dd-HH_mm
		Write-Host Backup will be created with name $timestamp -F green
		sc $ptxt "create system backup $timestamp -level full -comment $timestamp"
		Write-Host $ptxt created -F green

		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()
		Write-Host putty run -F green

		start $pscp "-scp -batch -P 22 -l $U -pw $P $($IP):/var/ns_sys_backup/$timestamp.tgz .\$($IP)_$($timestamp).tgz" -NoNewWindow -Wait
		Write-Host backup downloaded to (gi .\$($IP)_$($timestamp).tgz) -F green

		sc $ptxt "rm system backup $timestamp.tgz"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()
		Write-Host backup deleted -F green
	}
}

Function Config-NS{
	param($U,$P,$IP)
	If (Check -U $U -P $P -IP $IP){
		$timestamp = Get-Date -Format yyyy_MM_dd-HH_mm
		start $pscp "-scp -batch -P 22 -l $U -pw $P $IP`:/flash/nsconfig/ns.conf .\$($IP)_$($timestamp)_ns.conf" -NoNewWindow -Wait
		Write-Host config downloaded to (gi .\$($IP)_$($timestamp)_ns.conf) -F green
	}
}

Function Clean-NS{
	param($U,$P,$IP)
	If (Check -U $U -P $P -IP $IP){
		sc $ptxt "shell`ndf -h`nrm -r -f /var/core/*`nrm -r -f /var/crash/*`nrm -r -f /var/nsinstall/*`nrm -r -f /var/nstrace/*`nrm -r -f /var/tmp/*`nfind /var/log/ -mtime +7 -delete`nfind /var/nslog/ -mtime +7 -delete`nfind /var/nsproflog/ -mtime +7 -delete`nfind /var/nsproflog/ -mtime +7 -delete`nfind /var/nssynclog/ -mtime +7 -delete`nfind /var/nssynclog/ -mtime +7 -delete`nfind /var/nstmp/ -mtime +7 -delete`nfind /var/mps/log/ -mtime +7 -delete`ndf -h"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logappend" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()
		
		$varL = gc $plog | ? {$_ -match "/var" -and $_ -notmatch "find"}
		if ($varL.Count -eq 2) {
			$usedSpaceBefore = (($varL[0] -split '\s+').Trim()[2]).replace("G","")
			$usedSpaceAfter = (($varL[1] -split '\s+').Trim()[2]).replace("G","")
			$usedDifference = $usedSpaceBefore - $usedSpaceAfter
			Write-Host "used space before cleanup: ${usedSpaceBefore} GB" -F green
			Write-Host "used space after cleanup: ${usedSpaceAfter} GB" -F green
			Write-Host "space freed: ${usedDifference} GB" -F green
		}
	}
}

Function Upgrade-NS{
	param($U,$P,$IP,$Fw)
	If (Check -U $U -P $P -IP $IP){
		If (!($Fw)){
			$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
			$FileBrowser.Title = "Select the firmware file"
			$FileBrowser.Filter = "TGZ Files|build-*_nc_64.tgz"
			$null = $FileBrowser.ShowDialog()
			$FW = (gi $FileBrowser.FileName)
		}Else{
			If (Test-Path $FW){$FW = gi $FW}Else{Break}
		}
		$fwbase = $FW.BaseName
		$fwname = $FW.Name
		$fwpath = $FW.FullName

		sc $ptxt "shell`ncd /var/nsinstall`nmkdir -p $fwbase`nexit"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logoverwrite" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()

		$Active = $true
		foreach ($line in (gc $plog)){If ($line -match "Warning: You are connected to a secondary node"){$Active = $false;break}}
		If ($Active){
			$Reboot = [System.Windows.Forms.MessageBox]::Show("The $IP does not seem to be a passive node in the HA configuration or there might not be a HA configuration at all.`n`nThe upgrade will reboot the NetScaler and this might interfere your users.`n`nAre you sure you want to continue?", "Confirm Reboot?", [System.Windows.Forms.MessageBoxButtons]::YesNo)
			If ($Reboot -eq [System.Windows.Forms.DialogResult]::No){return}
		}
		Write-Host "Uploading Firmware $($fw.name)" -F green
		start $pscp "-scp -batch -P 22 -l $U -pw $P ""$FWPath"" $IP`:/var/nsinstall/$fwbase/$fwname" -NoNewWindow -Wait
		Write-Host "Upload Completed. Performing Upgrade" -F green

		Sleep 1
		sc $ptxt "shell`ncp /var/install/$fwname /var/nsinstall/$fwbase`nexit"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logoverwrite" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()
		
		sc $ptxt "shell`necho start`ncd /var/nsinstall/$fwbase`ntar -zxvf $fwname`n./installns -yYGDN`nexit"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logappend" -PassThru -NoNewWindow
		while ($true) {if ((gc $plog) -match "Rebooting"){break}Else{Write-host . -F green -NoNewLine;sleep 1}}
		Write-host . -F green
		Stop-Process -Id $process.id -Force

		sc .\upgrade-$IP.log (gc $plog | Select-Object -skip ((gc $plog | select-string -pattern start).Linenumber[0] - 1))
		If ($Cmdline){
			$logpath = (gi .\upgrade-$IP.log).FullName
			Write-Host "You can view the logfile $logpath for more details about the upgrade" -F green
		}Else{
			$ViewLog = [System.Windows.Forms.MessageBox]::Show("The upgrade completed, do you want to view the logfile?", "View upgrade logfile?", [System.Windows.Forms.MessageBoxButtons]::YesNo)
			if ($ViewLog -eq [System.Windows.Forms.DialogResult]::Yes){ii .\upgrade-$IP.log}
		}
	}
}

Function PlanFailover{
	param($U,$P,$IP,$FOTime)
	If (Check -U $U -P $P -IP $IP){
		If ($FOTime){
			$selectedDateTime = Get-Date $FOTime
		} Else {
			$PlanForm = New-Object System.Windows.Forms.Form
			$PlanForm.Text = "Plan Forced Failover"
			$PlanForm.Size = New-Object System.Drawing.Size(350, 150)
			$PlanForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

			$PlanLBL = New-Object System.Windows.Forms.Label
			$PlanLBL.Location = New-Object System.Drawing.Point 5, 5
			$PlanLBL.Size = New-Object System.Drawing.Size 350, 30
			$PlanLBL.Text = "Pick the time for the forced failover"
			$PlanLBL.Font = New-Object System.Drawing.Font("Arial",14,[System.Drawing.FontStyle]::"bold")
			$PlanForm.Controls.Add($PlanLBL)

			$dateTimePicker = New-Object System.Windows.Forms.DateTimePicker
			$dateTimePicker.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
			$dateTimePicker.CustomFormat = "yyyy-MM-dd HH:mm"
			$dateTimePicker.MinDate = (Get-Date).AddMinutes(1)
			$dateTimePicker.Location = New-Object System.Drawing.Point(10, 40)
			$PlanForm.Controls.Add($dateTimePicker)

			$OKB = New-Button "OK" 5 70 100 30
			$OKB.DialogResult = [System.Windows.Forms.DialogResult]::OK
			$PlanForm.Controls.Add($OKB)

			$CancelB = New-Button "Cancel" 110 70 100 30
			$CancelB.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
			$PlanForm.Controls.Add($CancelB)

			$result = $PlanForm.ShowDialog()
			If ($result -eq [System.Windows.Forms.DialogResult]::OK) {$selectedDateTime = $dateTimePicker.Value}
		}
		If ($selectedDateTime){
			$schtime = $selectedDateTime.ToString("HH:mm")
			$schdate = $selectedDateTime.ToString("dd/MM/yyyy",[System.Globalization.CultureInfo]::InvariantCulture)
			$schendtime = $selectedDateTime.Addminutes(1).ToString("HH:mm")
@"
[System.Net.ServicePointManager]::CheckCertificateRevocationList={`$false}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={`$true}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
irm "https://$IP/nitro/v1/config/login" -Method POST -Body (ConvertTo-JSON @{"login"=@{"username"="$U";"password"="$P";"timeout"="30"}}) -SessionVariable NSSession -ContentType "application/json"
irm "https://$IP/nitro/v1/config/hafailover?action=force" -Method POST -Body (ConvertTo-Json @{"hafailover"=@{"force"="true"}}) -WebSession `$NSSession -ContentType "application/json"
irm "https://$IP/nitro/v1/config/logout" -Method POST -Body (ConvertTo-JSON @{"logout"=@{}}) -WebSession `$NSSession -ContentType "application/json"
schtasks /change /tn NetScaler_Planned_Forced_Failover_$IP /ed $schdate /et $schendtime /Z
del `$PSCommandPath
"@ | Out-File $ENV:WINDIR\TEMP\NSForcedFailover-$IP.ps1
			Start cmd "/c schtasks /create /RU SYSTEM /IT /SC ONCE /sd $schdate /st $schtime /tn NetScaler_Planned_Forced_Failover_$IP /F /RL HIGHEST /tr ""powershell.exe -executionpolicy bypass -File $ENV:WINDIR\TEMP\NSForcedFailover-$IP.ps1""" -Verb RunAs
		}
	}
}

Function HAStatus {
	param($U,$P,$IP)
	If (Check -U $U -P $P -IP $IP){
		irm "https://$IP/nitro/v1/config/login" -Method POST -Body (ConvertTo-JSON @{"login"=@{"username"="$U";"password"="$P";"timeout"="30"}}) -SessionVariable NSSession -ContentType "application/json"
		$ha = (irm "https://$IP/nitro/v1/config/hanode" -Method GET -WebSession $NSSession -ContentType "application/json").hanode
		irm "https://$IP/nitro/v1/config/logout" -Method POST -Body (ConvertTo-JSON @{"logout"=@{}}) -WebSession $NSSession -ContentType "application/json"
		Write-Host $ha.ipaddress[0] = $ha.state[0] = $ha.hastatus[0]
		Write-Host $ha.ipaddress[1] = $ha.state[1] = $ha.hastatus[1]
	}
}

Function Failover {
	param($U,$P,$IP)
	If (Check -U $U -P $P -IP $IP){
		HAStatus -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text
		Write-Host -f yellow "Starting Failover"
		irm "https://$IP/nitro/v1/config/login" -Method POST -Body (ConvertTo-JSON @{"login"=@{"username"="$U";"password"="$P";"timeout"="30"}}) -SessionVariable NSSession -ContentType "application/json"
		irm "https://$IP/nitro/v1/config/hafailover?action=force" -Method POST -Body (ConvertTo-Json @{"hafailover"=@{"force"="true"}}) -WebSession $NSSession -ContentType "application/json"
		irm "https://$IP/nitro/v1/config/logout" -Method POST -Body (ConvertTo-JSON @{"logout"=@{}}) -WebSession $NSSession -ContentType "application/json"
		Write-Host -f green "Failover Completed"
		HAStatus -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text
	}
}

function togglepwd{
	if ($PasswordTB.UseSystemPasswordChar) {
        $PasswordTB.UseSystemPasswordChar = $false
        $ShowPwdB.Text = "Hide"
    } else {
        $PasswordTB.UseSystemPasswordChar = $true
        $ShowPwdB.Text = "Show"
    }
}

If ($UserName -and $Password -and $IP -and ($Backup -or $Config -or $Clean -or $Firmware -or $Failovertime)){
	$Cmdline = $true
	If ($Backup){Backup-NS -U $Username -P $Password -IP $IP}
	If ($Config){Config-NS -U $Username -P $Password -IP $IP}
	If ($Clean){Clean-NS -U $Username -P $Password -IP $IP}
	If ($Firmware){Upgrade-NS -U $Username -P $Password -IP $IP -Fw $Firmware}
	If ($Failovertime){PlanFailover -U $Username -P $Password -IP $IP -FOTime $Failovertime}
}Else{
	$Form = New-Object System.Windows.Forms.Form
	$Form.Text = "Easy NetScaler"
	$Form.Size = New-Object System.Drawing.Size(270, 275)
	$Form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

	New-Label "Easy NetScaler Tool" 10 0 200 25 14 bold
	New-Label "Username:" 5 30 75 20 10 regular
	$UserNameTB = New-TextBox 80 30 125 20
	If ($Username){$UserNameTB.Text = $UserName}Else{$UserNameTB.Text = "nsroot"}
	New-Label "Password:" 5 55 75 20 10 regular
	$PasswordTB = New-TextBox 80 55 125 20
	$PasswordTB.Text = "$Password"
	$PasswordTB.UseSystemPasswordChar = $true
	$ShowPwdB = New-Button "Show" 205 55 42 20
	$ShowPwdB.Add_Click({togglepwd})

	New-Label "IP:" 5 80 75 20 10 regular
	$IPTB = New-TextBox 80 80 125 20
	$IPTB.Text = $IP

	$BackupB = New-Button "Backup" 5 110 60 30
	$BackupB.Add_Click({Backup-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($BackupB)

	$ConfigB = New-Button "Config" 65 110 65 30
	$ConfigB.Add_Click({Config-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($ConfigB)

	$CleanB = New-Button "Clean NS FS" 130 110 80 30
	$CleanB.Add_Click({Clean-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($CleanB)

	$DownloadB = New-Button "Download Firmware" 5 140 125 30
	$DownloadB.Add_Click({Start "https://www.citrix.com/downloads/citrix-adc/"})
	$Form.Controls.Add($DownloadB)

	$UpgradeB = New-Button "Upgrade" 130 140 80 30
	$UpgradeB.Add_Click({Upgrade-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($UpgradeB)

	$PlanFailoverB = New-Button "Plan Forced Failover" 5 170 125 30
	$PlanFailoverB.Add_Click({PlanFailover -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($PlanFailoverB)

	$HAB = New-Button "HA Status" 130 170 80 30
	$HAB.Add_Click({HAStatus -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($HAB)

	$FailoverB = New-Button "Failover NOW" 5 200 125 30
	$FailoverB.Add_Click({Failover -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text})
	$Form.Controls.Add($FailoverB)

	$Form.ShowDialog()
}

del $ptxt, $putty, $pscp -EA 0
