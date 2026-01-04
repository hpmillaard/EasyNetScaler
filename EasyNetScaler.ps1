<#
.SYNOPSIS
	Create a backup of your NetScaler. Perform an Upgrade of your NetScaler. Clean the filesystem of your NetScaler. Perform failover.
.DESCRIPTION
	This script has several options to backup, clean, upgrade and failover your NetScaler. If no command line options are given or you just run the script through the right click menu in Explorer, the script will show a GUI.

	Note: when a NetScaler presents an untrusted or default Citrix certificate the script will temporarily accept the appliance certificate for the duration of the session (per-host), and will restore the original certificate validation settings on logout. For a permanent fix, import the management certificate to `LocalMachine\Root`.
.PARAMETER Help
	Display the detailed information about this script
.PARAMETER Username
	NetScaler Username with enough access
.PARAMETER Password
	NetScaler Username password
.PARAMETER IP
	Management IP (NSIP) or hostname of the NetScaler appliance. Used to connect to the ADC.
.PARAMETER Backup
	Create a full backup of the NetScaler system files.
.PARAMETER Config
	Create a backup from the `ns.conf` configuration file only.
.PARAMETER Clean
	Clean the NetScaler filesystem (old logs, core files, temporary files).
.PARAMETER Firmware
	The path to the firmware `.tgz` file used for upgrades.
.PARAMETER Failovertime
	The date and time that the failover should occur. A Scheduled task will be created that will run at the planned time.
.PARAMETER FailoverNow
	Make the passive NetScaler the active one.
.PARAMETER Upgradetime
	The date and time that a planned upgrade should occur (used with `-Firmware`).
.PARAMETER vServerReport
	Generate a CSV report of vServers and save it to the script folder (or provide an output path).
.PARAMETER CompareReports
	Provide two CSV report file paths to compare vServer state changes (comma separated).
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
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -FailoverNow
	Make the passive NetScaler the active one
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Firmware C:\Temp\Build-14.1-12.35_nc_64.tgz
	Upgrade the NetScaler with the firmware
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Failovertime "1-2-2025 18:00"
	Plan forced failover
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -vServerReport
	Generate a vServer CSV report and save it to the script folder.
.EXAMPLE
	.\EasyNetScaler.ps1 -CompareReports C:\reports\before.csv,C:\reports\after.csv
	Compare two vServer reports and display a summary of changes.
.EXAMPLE
	.\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup -Clean -Firmware C:\Temp\Build-14.1-12.35_nc_64.tgz -Failovertime "1-2-2025 18:00"
	Backup, Clean the FileSystem and upgrade the NetScaler with the firmware and plan the force failover
.NOTES
	File name	: EasyNetScaler.ps1
	Author		: Harm Peter Millaard
	Requires	: PowerShell v5.1 and up, .NET Framework with TLS 1.2 support (Windows Server 2016 / Windows 10 or newer recommended)
			ADC 12.1 and higher
			Internet connection to download PuTTY and PSCP when needed

	Security/Certificates:
	 - The script forces `Tls12` for Nitro API calls to ensure modern TLS is used.
	 - To permanently trust a NetScaler certificate (recommended), export the management certificate from the appliance and import it on the machine running the script:
	   `Import-Certificate -FilePath 'C:\temp\netscaler.cer' -CertStoreLocation Cert:\LocalMachine\Root`
	 - The script uses a per-host temporary validation override only for the target NetScaler and restores the original settings on logout to avoid a global, persistent bypass.
.LINK
	https://github.com/hpmillaard/EasyNetScaler
#>

param(
	[ValidateNotNullOrEmpty()][string]$Username,
	[ValidateNotNullOrEmpty()][string]$Password,
	[ValidateNotNullOrEmpty()][string]$IP,
	[switch]$Backup,
	[switch]$Config,
	[switch]$Clean,
	[string]$Firmware,
	[datetime]$Failovertime,
	[datetime]$Upgradetime,
	[switch]$FailoverNow,
	[switch]$vServerReport,
	[string[]]$CompareReports
)

$ScriptVersion = '2.0.0'

$putty = "$PSScriptRoot\putty.exe"
$pscp = "$PSScriptRoot\pscp.exe"

Add-Type -AN System.Windows.Forms
Add-Type -AN System.Drawing
Function msgbox($Text) { $r = [System.Windows.Forms.MessageBox]::Show($Text, $Text, [System.Windows.Forms.MessageBoxButtons]::OK) }

Function New-Label ($TargetForm, $Label, $X=5, $Y=5, $Width=50, $Height=20, $FontSize=10, $FontStyle='regular') {
	$LabelControl = New-Object System.Windows.Forms.Label
	$LabelControl.Location = New-Object System.Drawing.Point $X, $Y
	$LabelControl.Size = New-Object System.Drawing.Size $Width, $Height
	$LabelControl.Text = $Label
	$LabelControl.Font = New-Object System.Drawing.Font("Arial", $FontSize, [System.Drawing.FontStyle]::$FontStyle)
	$null = $TargetForm.Controls.Add($LabelControl)
	$LabelControl
}
Function New-TextBox ($TargetForm, $X=55, $Y=5, $Width=305, $Height=20) {
	$TB = New-Object System.Windows.Forms.TextBox
	$TB.Location = New-Object System.Drawing.Point $X, $Y
	$TB.Size = New-Object System.Drawing.Size $Width, $Height
	$null = $TargetForm.Controls.Add($TB)
	$TB
}
Function New-Button ($TargetForm, $Text, $X, $Y, $Width, $Height) {
	$Button = New-Object System.Windows.Forms.Button
	$Button.Location = New-Object System.Drawing.Point $X, $Y
	$Button.Size = New-Object System.Drawing.Size $Width, $Height
	$Button.Text = $Text
	$null = $TargetForm.Controls.Add($Button)
	$Button
}

Function New-DateTimePicker ($TargetForm, $X, $Y, $Width, $Height) {
	$dtp = New-Object System.Windows.Forms.DateTimePicker
	$dtp.Format = [System.Windows.Forms.DateTimePickerFormat]::Custom
	$dtp.CustomFormat = "yyyy-MM-dd HH:mm"
	$now = Get-Date
	$nextHalfHour = $now.AddMinutes(30 - ($now.Minute % 30)).AddSeconds(-$now.Second).AddMilliseconds(-$now.Millisecond)
	$dtp.Value = $nextHalfHour
	$dtp.Location = New-Object System.Drawing.Point $X, $Y
	$dtp.Size = New-Object System.Drawing.Size $Width, $Height
	$null = $TargetForm.Controls.Add($dtp)
	return $dtp
}

Function Check {
	param($U, $P, $IP, $Port)
	If (!(Test-Path $putty)) { Start-BitsTransfer 'https://the.earth.li/~sgtatham/putty/latest/w32/putty.exe' $putty }
	If (!(Test-Path $pscp)) { Start-BitsTransfer 'https://the.earth.li/~sgtatham/putty/latest/w32/pscp.exe' $pscp }
	If ([string]::IsNullOrEmpty($U)) { msgbox "Username can't be empty"; return $false }
	If ([string]::IsNullOrEmpty($P)) { msgbox "Password can't be empty"; return $false }
	If ([string]::IsNullOrEmpty($IP)) { msgbox "IP can't be empty"; return $false }
	try {
		$tcpClient = New-Object System.Net.Sockets.TcpClient
		$tcpClient.Connect($IP, $Port)
		if ($tcpClient.Connected) {
			$tcpClient.Close()
			$ptxt = "$PSScriptRoot\putty-check.txt"
			Set-Content $ptxt "exit"
			$process = Start-Process $putty "-ssh $IP -l $U -pw $P -m $ptxt" -PassThru -NoNewWindow
			$wshell = New-Object -ComObject WScript.Shell
			$maxTries = 40
			for ($i = 0; $i -lt $maxTries; $i++) {
				if ($wshell.AppActivate("PuTTY Security Alert")) {
					Start-Sleep -Milliseconds 200
					$wshell.SendKeys('%a')
					break
				}
				if ($process.HasExited) { break }
				Start-Sleep -Milliseconds 250
			}
			$process.WaitForExit()
			$process.Close()
			del $ptxt -EA 0
			return $true
		} else {Write-Host "Unable to connect to $IP over TCP port $Port" -F Red }
	}
	   catch {
		   Write-Host "Try failed: Unable to connect to $IP over TCP port $Port" -F Red
		   Write-Host $_.Exception.Message -F Red
	   }
	return $false
}

Function Login {
	param($U, $P, $IP)
	If (!(Check -U $U -P $P -IP $IP -Port 443)) { return $false }
	# Disable CRL checks (optional) and set per-host certificate validation to avoid global bypass
	[System.Net.ServicePointManager]::CheckCertificateRevocationList = $false
	$script:OriginalCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
		param($sender, $cert, $chain, $sslPolicyErrors)
		try {
			$req = $sender -as [System.Net.HttpWebRequest]
			if ($req -and $req.RequestUri.Host -eq $IP) { return $true }
		} catch {}
		if ($script:OriginalCertificateCallback) { return & $script:OriginalCertificateCallback $sender, $cert, $chain, $sslPolicyErrors }
		return ($sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
	}
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	If ((get-host).version.Major -gt 5) { $Global:params = @{SkipCertificateCheck = $true; ContentType = "application/json" } } else { $Global:params = @{ContentType = "application/json" } }
	$params.Remove("WebSession")
	$Login = irm "https://$IP/nitro/v1/config/login" -Method POST -Body (ConvertTo-JSON @{"login" = @{"username" = "$U"; "password" = "$P"; "timeout" = "30" } }) -SessionVariable LocalNSSession @params
	If ($Login.errorcode -eq 0) { $params.Add("WebSession", $LocalNSSession); return $true }
	return $false
}

Function Logout {
	$Logout = irm "https://$IP/nitro/v1/config/logout" -Method POST -Body (ConvertTo-JSON @{"logout" = @{} }) @params
	# Restore original certificate validation settings
	if ($script:OriginalCertificateCallback -ne $null) {
		[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:OriginalCertificateCallback
		Remove-Variable -Scope Script -Name OriginalCertificateCallback -ErrorAction SilentlyContinue
	}
	[System.Net.ServicePointManager]::CheckCertificateRevocationList = $true
	$Logout
}

Function Backup-NS {
	param($U, $P, $IP)
	If (!(Login -U $U -P $P -IP $IP)) { return }
	$timestamp = Get-Date -Format yyyy_MM_dd-HH_mm
	$BCreate = irm "https://$IP/nitro/v1/config/systembackup?action=create" -Method POST -Body (ConvertTo-Json @{"systembackup" = @{"filename" = $timestamp; "level" = "full"; "comment" = $timestamp } }) @params
	$BDown = irm "https://$IP/nitro/v1/config/systemfile?args=filename:$timestamp.tgz,filelocation:%2Fvar%2Fns_sys_backup" @params
	$BDel = irm "https://$IP/nitro/v1/config/systembackup/$timestamp.tgz" -Method DELETE @params
	[IO.File]::WriteAllBytes("$($PSScriptRoot)\$($IP)_$($timestamp).tgz", [Convert]::FromBase64String($BDown.systemfile.filecontent))
	Write-Host "backup downloaded to $PSScriptRoot\$($IP)_$($timestamp).tgz" -F green
}

Function Config-NS {
	param($U, $P, $IP)
	If (!(Login -U $U -P $P -IP $IP)) { return }
	$timestamp = Get-Date -Format yyyy_MM_dd-HH_mm
	$CDown = irm "https://$IP/nitro/v1/config/systemfile?args=filename:ns.conf,filelocation:%2Fflash%2Fnsconfig" @params
	[IO.File]::WriteAllBytes("$($PSScriptRoot)\$($IP)_$($timestamp)_ns.conf", [Convert]::FromBase64String($CDown.systemfile.filecontent))
	Write-Host "config downloaded to $($PSScriptRoot)\$($IP)_$($timestamp)_ns.conf" -F green
}

Function Clean-NS {
	param($U, $P, $IP)
	if (Check -U $U -P $P -IP $IP -Port 22) {
		$time = Get-Date -Format yyMMddHHmm
		$ptxt = "$PSScriptRoot\putty-$time.txt"
		$plog = "$PSScriptRoot\putty-$time.log"

		sc $ptxt "shell`ndf -h`nrm -r -f /var/core/*`nrm -r -f /var/crash/*`nrm -r -f /var/nsinstall/*`nrm -r -f /var/nstrace/*`nrm -r -f /var/tmp/*`nfind /var/log/ -mtime +7 -delete`nfind /var/nslog/ -mtime +7 -delete`nfind /var/nsproflog/ -mtime +7 -delete`nfind /var/nsproflog/ -mtime +7 -delete`nfind /var/nssynclog/ -mtime +7 -delete`nfind /var/nssynclog/ -mtime +7 -delete`nfind /var/nstmp/ -mtime +7 -delete`nfind /var/mps/log/ -mtime +7 -delete`ndf -h"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logoverwrite" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()

		$varL = gc $plog | ? { $_ -match "/var" -and $_ -notmatch "find" }
		if ($varL.Count -eq 2) {
			$usedSpaceBefore = (($varL[0] -split '\s+').Trim()[2]).replace("G", "")
			$usedSpaceAfter = (($varL[1] -split '\s+').Trim()[2]).replace("G", "")
			$usedDifference = $usedSpaceBefore - $usedSpaceAfter
			Write-Host "used space before cleanup: ${usedSpaceBefore} GB" -F Green
			Write-Host "used space after cleanup: ${usedSpaceAfter} GB" -F Green
			Write-Host "space freed: ${usedDifference} GB" -F Green
		}
		del $ptxt, $plog -EA 0
	}
}

Function Upgrade-NS {
	param($U, $P, $IP, $Fw)
	If (Check -U $U -P $P -IP $IP -Port 22) {
		$time = get-date -Format yyMMddHHmm
		$ptxt = "$PSScriptRoot\putty-$time.txt"
		$plog = "$PSScriptRoot\putty-$time.log"
		If (!($Fw)) {
			$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
			$FileBrowser.Title = "Select the firmware file"
			$FileBrowser.Filter = "TGZ Files|build-*_nc_64.tgz"
			$null = $FileBrowser.ShowDialog()
			$FW = (gi $FileBrowser.FileName)
		} else {
			if (Test-Path $FW) { $FW = gi $FW } else { Break }
		}
		$fwbase = $FW.BaseName
		$fwname = $FW.Name
		$fwpath = $FW.FullName

		sc $ptxt "shell`ncd /var/nsinstall`nmkdir -p $fwbase`nexit"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logoverwrite" -PassThru -NoNewWindow
		$process.WaitForExit()
		$process.Close()

		$Active = $true
		foreach ($line in (gc $plog)) { If ($line -match "Warning: You are connected to a secondary node") { $Active = $false; break } }
		If ($Active) {
			$Reboot = [System.Windows.Forms.MessageBox]::Show("The $IP does not seem to be a passive node in the HA configuration or there might not be a HA configuration at all.`n`nThe upgrade will reboot the NetScaler and this might interfere your users.`n`nAre you sure you want to continue?", "Confirm Reboot?", [System.Windows.Forms.MessageBoxButtons]::YesNo)
			If ($Reboot -eq [System.Windows.Forms.DialogResult]::No) { return }
		}
		Write-Host "Uploading Firmware $($fw.name)" -F green
		start $pscp "-scp -batch -P 22 -l $U -pw $P ""$FWPath"" $IP`:/var/nsinstall/$fwbase/$fwname" -NoNewWindow -Wait
		Write-Host "Upload Completed. Performing Upgrade" -F green

		sc $ptxt "shell`necho start`ncd /var/nsinstall/$fwbase`ntar -zxvf $fwname`nrm $fwname`n./installns -g -G -N -y -M -D`nexit"
		$process = start $putty "-ssh $IP -l $U -pw $P -m $ptxt -sessionlog $plog -logoverwrite" -PassThru -NoNewWindow
		while ($true) {
			$content = gc $plog
			if ($content -match "Rebooting") {
				Write-Host "`nReboot detected." -F Green
				Write-Host "Waiting for SSH (port 22) to become available again..." -F Yellow
				Sleep 30
				while (!(Check -U $U -P $P -IP $IP -Port 22)) {
					Write-Host "." -NoNewline -F Yellow
					Sleep 5
				}
				Write-Host "`nSSH is available again on $IP" -F Green
				break
			} elseif ($content -match "ERROR:") {
				Write-Host "`nERROR DETECTED!" -F Red
				break
			} else {
				Write-Host "." -F Green -NoNewline
				Sleep 1
			}
		}
		Write-host ""
		Stop-Process -Id $process.id -Force

		sc "$PSScriptRoot\upgrade-$IP.log" (gc $plog | Select-Object -skip ((gc $plog | select-string -pattern start).Linenumber[0]))
		If ($Cmdline) {
			$logpath = (gi "$PSScriptRoot\upgrade-$IP.log").FullName
			Write-Host "You can view the logfile $logpath for more details about the upgrade" -F green
		} Else {
			$ViewLog = [System.Windows.Forms.MessageBox]::Show("The upgrade completed, do you want to view the logfile?", "View upgrade logfile?", [System.Windows.Forms.MessageBoxButtons]::YesNo)
			if ($ViewLog -eq [System.Windows.Forms.DialogResult]::Yes) { ii "$PSScriptRoot\upgrade-$IP.log" }
		}
		del $ptxt, $plog -EA 0
	}
}

Function PlanUpgrade {
	param($U, $P, $IP, $Fw, $UPTime)
	if ($UPTime) {
		$selectedDateTime = Get-Date $UPTime
	} else {
		$PlanForm = New-Object System.Windows.Forms.Form
		$PlanForm.Text = "Plan Upgrade"
		$PlanForm.Size = New-Object System.Drawing.Size(350, 150)
		$PlanForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

		$null = New-Label $PlanForm "Pick the time for the upgrade" 5 5 350 30 14 'bold'
		$dateTimePicker = New-DateTimePicker $PlanForm 10 40 200 20

		$OKB = New-Button $PlanForm "OK" 5 70 100 30
		$OKB.DialogResult = [System.Windows.Forms.DialogResult]::OK

		$CancelB = New-Button $PlanForm "Cancel" 110 70 100 30
		$CancelB.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

		$result = $PlanForm.ShowDialog()
		if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $selectedDateTime = $dateTimePicker.Value }
	}
	if (!$Fw) {
		$FileBrowser = New-Object System.Windows.Forms.OpenFileDialog
		$FileBrowser.Title = "Select the firmware file"
		$FileBrowser.Filter = "TGZ Files|build-*_nc_64.tgz"
		$null = $FileBrowser.ShowDialog()
		if ([string]::IsNullOrEmpty($FileBrowser.FileName)) { Write-Host "No firmware selected, cancelling planned upgrade." -F Yellow; return }
		$Fw = $FileBrowser.FileName
	}
	if ($selectedDateTime) {
		$schtime = $selectedDateTime.ToString("HH:mm")
		$schdate = $selectedDateTime.ToString("dd/MM/yyyy", [System.Globalization.CultureInfo]::InvariantCulture)
		$scriptPath = (Get-Item $PSCommandPath).FullName
		@"
PowerShell -ExecutionPolicy Bypass -File '$scriptPath' -Username $U -Password $P -IP $IP -Firmware '$Fw'
schtasks /delete /tn NetScaler_Planned_Upgrade_$IP /F
del `$PSCommandPath
"@ | Out-File $ENV:WINDIR\TEMP\NSPlannedUpgrade-$IP.ps1
		Start-Process cmd "/c schtasks /create /IT /SC ONCE /sd $schdate /st $schtime /tn NetScaler_Planned_Upgrade_$IP /F /RL HIGHEST /tr `"powershell.exe -executionpolicy bypass -File $ENV:WINDIR\TEMP\NSPlannedUpgrade-$IP.ps1`"" -Verb RunAs
		Write-Host "Planned upgrade scheduled for $selectedDateTime" -F Green
	}
}

Function Version {
	param($U, $P, $IP)
	If (!(Login -U $U -P $P -IP $IP)) { return }
	$version = (irm "https://$IP/nitro/v1/config/nsversion" -Method GET @params).nsversion.version
	Logout
	Write-Host -f cyan $IP = $version
}

Function Failover {
	param($U, $P, $IP)
	If (!(Check -U $U -P $P -IP $IP -Port 443)) { return }
	HAStatus  -U $U -P $P -IP $IP
	Write-Host -f yellow "Starting Failover $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')"
	If (!(Login -U $U -P $P -IP $IP)) { return }
	$R = irm "https://$IP/nitro/v1/config/hafailover?action=force" -Method POST -Body (ConvertTo-Json @{"hafailover" = @{"force" = "true" } }) @params
	$R
	Write-Host -f green "Failover Completed $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff')"
	HAStatus -U $U -P $P -IP $IP
}

Function PlanFailover($U, $P, $IP, $FOTime) {
	if (Check -U $U -P $P -IP $IP -Port 443) {
		if ($FOTime) {
			$selectedDateTime = Get-Date $FOTime
		} else {
			$PlanForm = New-Object System.Windows.Forms.Form
			$PlanForm.Text = "Plan Forced Failover"
			$PlanForm.Size = New-Object System.Drawing.Size(350, 150)
			$PlanForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

			$null = New-Label $PlanForm "Pick the time for the forced failover" 5 5 350 30 14 'bold'
			$dateTimePicker = New-DateTimePicker $PlanForm 10 40 200 20

			$OKB = New-Button $PlanForm "OK" 5 70 100 30
			$OKB.DialogResult = [System.Windows.Forms.DialogResult]::OK

			$CancelB = New-Button $PlanForm "Cancel" 110 70 100 30
			$CancelB.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

			$result = $PlanForm.ShowDialog()
			if ($result -eq [System.Windows.Forms.DialogResult]::OK) { $selectedDateTime = $dateTimePicker.Value }
		}
		if ($selectedDateTime) {
			$schtime = $selectedDateTime.ToString("HH:mm")
			$schdate = $selectedDateTime.ToString("dd/MM/yyyy", [System.Globalization.CultureInfo]::InvariantCulture)
			$schendtime = $selectedDateTime.Addminutes(1).ToString("HH:mm")
			@"
[System.Net.ServicePointManager]::CheckCertificateRevocationList=`$false
`$script:OriginalCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = {
	param(`$sender, `$cert, `$chain, `$sslPolicyErrors)
	try {
		`$req = `$sender -as [System.Net.HttpWebRequest]
		if (`$req -and `$req.RequestUri.Host -eq '$IP') { return `$true }
	} catch {}
	if (`$script:OriginalCertificateCallback) { return & `$script:OriginalCertificateCallback `$sender, `$cert, `$chain, `$sslPolicyErrors }
	return (`$sslPolicyErrors -eq [System.Net.Security.SslPolicyErrors]::None)
}
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
irm "https://$IP/nitro/v1/config/login" -Method POST -Body (ConvertTo-JSON @{"login"=@{"username"="$U";"password"="$P";"timeout"="30"}}) -SessionVariable NSSession -ContentType "application/json"
irm "https://$IP/nitro/v1/config/hafailover?action=force" -Method POST -Body (ConvertTo-Json @{"hafailover"=@{"force"="true"}}) -WebSession `$NSSession -ContentType "application/json"
irm "https://$IP/nitro/v1/config/logout" -Method POST -Body (ConvertTo-JSON @{"logout"=@{}}) -WebSession `$NSSession -ContentType "application/json"
# Restore original certificate validation settings
if (`$script:OriginalCertificateCallback -ne `$null) {
	[System.Net.ServicePointManager]::ServerCertificateValidationCallback = `$script:OriginalCertificateCallback
	Remove-Variable -Scope Script -Name OriginalCertificateCallback -ErrorAction SilentlyContinue
}
[System.Net.ServicePointManager]::CheckCertificateRevocationList = `$true
schtasks /change /tn NetScaler_Planned_Forced_Failover_$IP /ed $schdate /et $schendtime /Z
del `$PSCommandPath
"@ | Out-File $ENV:WINDIR\TEMP\NSForcedFailover-$IP.ps1
			Start-Process cmd "/c schtasks /create /IT /SC ONCE /sd $schdate /st $schtime /tn NetScaler_Planned_Forced_Failover_$IP /F /RL HIGHEST /tr `"powershell.exe -executionpolicy bypass -File $ENV:WINDIR\TEMP\NSForcedFailover-$IP.ps1`"" -Verb RunAs
			Write-Host "Planned failover scheduled for $selectedDateTime" -F Green
		}
	}
}

Function HAStatus {
	param($U, $P, $IP)
	If (!(Login -U $U -P $P -IP $IP)) { return }
	$ha = (irm "https://$IP/nitro/v1/config/hanode" -Method GET @params).hanode
	Logout
	Write-Host $ha.ipaddress[0] = $ha.state[0] = $ha.hastatus[0]
	Write-Host $ha.ipaddress[1] = $ha.state[1] = $ha.hastatus[1]
}

Function Get-vServerStatus {
	param($U, $P, $IP)
	if (!(Login -U $U -P $P -IP $IP)) { return }
	$vServers = @()
	$types = @(
		@{ key = 'lbvserver'; type = 'LB'; health = $true; ip = $true; port = $true },
		@{ key = 'csvserver'; type = 'CS'; health = $true; ip = $true; port = $true },
		@{ key = 'vpnvserver'; type = 'VPN'; health = $false; ip = $true; port = $true },
		@{ key = 'gslbvserver'; type = 'GSLB'; health = $true; ip = $false; port = $false }
	)
	$ha = (irm "https://$IP/nitro/v1/config/hanode" -Method GET @params).hanode
	$nodeState = if ($ha.state[0] -eq "Primary") { "Primary" } else { "Secondary" }
	$version = (irm "https://$IP/nitro/v1/config/nsversion" -Method GET @params).nsversion.version
	foreach ($t in $types) {
		try {
			$data = (irm "https://$IP/nitro/v1/config/$($t.key)" -Method GET @params).$($t.key)
			foreach ($vs in $data) {
				$vServers += [PSCustomObject]@{
					Type           = $t.type
					Name           = $vs.name
					State          = $vs.curstate
					EffectiveState = $vs.effectivestate
					Health         = if ($t.health) { $vs.health } else { '-' }
					IPAddress      = if ($t.ip) { $vs.ipv46 } else { '-' }
					Port           = if ($t.port) { $vs.port } else { '-' }
					ServiceType    = $vs.servicetype
				}
			}
		} catch { Write-Host "Could not retrieve $($t.type) vServers" -F Yellow }
	}
	Logout
	return @{
		IP        = $IP
		NodeState = $nodeState
		Version   = $version
		Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"
		vServers  = $vServers
	}
}

Function Export-vServerReport {
	param($U, $P, $IP, $OutputPath)
	$r = Get-vServerStatus -U $U -P $P -IP $IP
	if (!$r) { return }
	if (!$OutputPath) {
		$ts = Get-Date -Format yyyy-MM-dd_HH-mm
		$safeIP = $r.IP -replace '[^a-zA-Z0-9._-]', '_'
		$safeNode = $r.NodeState -replace '[^a-zA-Z0-9._-]', '_'
		$safeVer = $r.Version
		if ($safeVer -match 'NS([\d.]+)[^\d]*Build[_ ]([\d.]+)') {
			$safeVer = "$($Matches[1])_$($Matches[2])"
		}
		else {
			$safeVer = $safeVer -replace '[^a-zA-Z0-9._-]', '_'
		}
		$OutputPath = "$PSScriptRoot\vServerReport_${safeIP}_${safeNode}_${safeVer}_$ts.csv"
	}
	$cols = 'Type', 'Name', 'State', 'EffectiveState', 'Health', 'IPAddress', 'Port', 'ServiceType'
	$r.vServers | Select-Object $cols | Export-Csv $OutputPath -NoTypeInformation -Encoding UTF8
	$up = ($r.vServers | Where-Object State -eq 'UP').Count
	$down = ($r.vServers | Where-Object State -eq 'DOWN').Count
	$other = $r.vServers.Count - $up - $down
	Write-Host "`nvServer Report for $($r.IP) ($($r.NodeState))" -F Cyan
	Write-Host "Version: $($r.Version)" -F Cyan
	Write-Host "Total: $($r.vServers.Count) | UP: $up | DOWN: $down" -F White
	if ($other) { Write-Host "OTHER: $other" -F Yellow }
	Write-Host "Report saved to: $OutputPath" -F Green
	return $OutputPath
}

Function Compare-vServerReport {
	param($Report1Path, $Report2Path)
	if (!(Test-Path $Report1Path) -or !(Test-Path $Report2Path)) { Write-Host "One or both report files not found!" -F Red; return}
	$r1 = Import-Csv $Report1Path
	$r2 = Import-Csv $Report2Path
	Write-Host "`n========== vServer Comparison Report =========" -F Cyan
	Write-Host "Report 1: $Report1Path" -F Yellow
	Write-Host "Report 2: $Report2Path" -F Yellow
	Write-Host "===============================================`n" -F Cyan
	$diffs = @()
	$names1 = $r1 | ForEach-Object { "$_($($_.Type))" }
	$names2 = $r2 | ForEach-Object { "$_($($_.Type))" }
	foreach ($a in $r1) {
		$b = $r2 | Where-Object { $_.Name -eq $a.Name -and $_.Type -eq $a.Type }
		if ($b) {
			if ($a.State -ne $b.State) {
				$chg = if ($a.State -eq 'UP' -and $b.State -ne 'UP') { 'DEGRADED' } elseif ($a.State -ne 'UP' -and $b.State -eq 'UP') { 'IMPROVED' } else { 'CHANGED' }
				$diffs += "[$($a.Type)] $($a.Name): $($a.State) -> $($b.State) ($chg)"
			}
		} else { $diffs += "[$($a.Type)] $($a.Name) missing in report 2 (was $($a.State))" }
	}
	foreach ($b in $r2 | Where-Object { ($r1 | Where-Object { $_.Name -eq $b.Name -and $_.Type -eq $b.Type }).Count -eq 0 }) {
		$diffs += "[$($b.Type)] $($b.Name) new in report 2 ($($b.State))"
	}
	$up1 = ($r1 | Where-Object State -eq 'UP').Count
	$down1 = ($r1 | Where-Object State -eq 'DOWN').Count
	$up2 = ($r2 | Where-Object State -eq 'UP').Count
	$down2 = ($r2 | Where-Object State -eq 'DOWN').Count
	Write-Host "Summary:" -F White
	Write-Host "  Report 1: Total=$($r1.Count), UP=$up1, DOWN=$down1" -F White
	Write-Host "  Report 2: Total=$($r2.Count), UP=$up2, DOWN=$down2" -F White
	if ($diffs.Count) {
		Write-Host "`nDifferences:" -F Yellow
		$diffs | ForEach-Object { Write-Host $_ -F Yellow }
		$comparisonPath = "$PSScriptRoot\vServerComparison_$(Get-Date -Format 'yyyy_MM_dd-HH_mm').txt"
		"`nDifferences:" | Out-File $comparisonPath -Append -Encoding UTF8
		$diffs | Out-File $comparisonPath -Append -Encoding UTF8
		Write-Host "`nComparison saved to: $comparisonPath" -F Green
	} else {
		Write-Host "`nNo differences found! All vServers have the same state. No comparison file created." -F Green
	}
}

Function Show-CompareDialog {
		$CompareForm = New-Object System.Windows.Forms.Form
		$CompareForm.Text = "Compare vServer Reports"
		$CompareForm.Size = New-Object System.Drawing.Size(450, 150)
		$CompareForm.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

		$labels = @("Before:", "After:")
		$TBs = @()
		for ($i = 0; $i -lt 2; $i++) {
			$y = 10 + 30*$i
			New-Label $CompareForm $labels[$i] 5 $y
			$TBs += New-TextBox $CompareForm 55 $y
			$Browse = New-Button $CompareForm "Browse" 365 (8 + 30*$i) 65 25
			$Browse.Add_Click({
				$fb = New-Object System.Windows.Forms.OpenFileDialog
				$fb.Title = "Select Report $($labels[$i].Trim(':'))"
				$fb.Filter = "CSV Files|*.csv"
				$fb.InitialDirectory = $PSScriptRoot
				if ($fb.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) { $TBs[$i].Text = $fb.FileName }
			}.GetNewClosure())
		}

		$CompareB = New-Button $CompareForm "Compare" 5 75 100 30
		$CompareB.Add_Click({
			if ($TBs[0].Text -and $TBs[1].Text) {
				Compare-vServerReport -Report1Path $TBs[0].Text -Report2Path $TBs[1].Text
				$CompareForm.Close()
			} else {
				[System.Windows.Forms.MessageBox]::Show("Please select both report files", "Error", "OK", "Error")
			}
		})

		$CancelB = New-Button $CompareForm "Cancel" 110 75 100 30
		$CancelB.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

		$null = $CompareForm.ShowDialog()
}

Function Update-Script {
	try {
		$RemoteScript = irm "https://raw.githubusercontent.com/hpmillaard/EasyNetScaler/main/EasyNetScaler.ps1" -UseBasicParsing
		$LatestVersion = if ($RemoteScript -match '\$ScriptVersion\s*=\s*[''"]([0-9\.]+)[''"]') { $Matches[1] } else { throw "Version not found" }
		
		if ([Version]$LatestVersion -gt [Version]$ScriptVersion) {
			if ([System.Windows.Forms.MessageBox]::Show("New version ($LatestVersion) available!`n`nUpdate now?", "Update", "YesNo", "Question") -eq "Yes") {
				$RemoteScript | Out-File "$ENV:TEMP\update.ps1" -Encoding UTF8
				Move-Item "$ENV:TEMP\update.ps1" $PSCommandPath -Force
				Write-Host "Updated to version $LatestVersion! Restarting..." -F Green
				$restartArgs = "-File `"$PSCommandPath`""
				if ($Username) { $restartArgs += " -Username $Username" }
				if ($Password) { $restartArgs += " -Password $Password" }
				if ($IP) { $restartArgs += " -IP $IP" }
				Start-Process PowerShell $restartArgs
				$Form.Close()
				exit
			}
		} else { [System.Windows.Forms.MessageBox]::Show("Already latest version ($ScriptVersion)!", "Up to date", "OK", "Information") }
	}
	catch { [System.Windows.Forms.MessageBox]::Show("Update failed: $($_.Exception.Message)", "Error", "OK", "Error") }
}

function TogglePWD {
	if ($PasswordTB.UseSystemPasswordChar) {
		$PasswordTB.UseSystemPasswordChar = $false
		$ShowPwdB.Text = "Hide"
	} else {
		$PasswordTB.UseSystemPasswordChar = $true
		$ShowPwdB.Text = "Show"
	}
}

if ($CompareReports -and $CompareReports.Count -eq 2) {
	$Cmdline = $true
	Compare-vServerReport -Report1Path $CompareReports[0] -Report2Path $CompareReports[1]
} elseif ($UserName -and $Password -and $IP -and ($Backup -or $Config -or $Clean -or $Firmware -or $Failovertime -or $Upgradetime -or $vServerReport)) {
	$Cmdline = $true
	if ($Backup) { Backup-NS -U $Username -P $Password -IP $IP }
	if ($Config) { Config-NS -U $Username -P $Password -IP $IP }
	if ($Clean) { Clean-NS -U $Username -P $Password -IP $IP }
	if ($vServerReport) { Export-vServerReport -U $Username -P $Password -IP $IP }
	if ($Firmware) { Upgrade-NS -U $Username -P $Password -IP $IP -Fw $Firmware }
	if ($Failovertime) { PlanFailover -U $Username -P $Password -IP $IP -FOTime $Failovertime }
	if ($Upgradetime -and $Firmware) { PlanUpgrade -U $Username -P $Password -IP $IP -UPTime $Upgradetime }
	if ($FailoverNow) { Failover -U $Username -P $Password -IP $IP }
} else {
	$Form = New-Object System.Windows.Forms.Form
	$Form.Text = "Easy NetScaler - v$ScriptVersion"
	$Form.Size = New-Object System.Drawing.Size(335, 300)
	$Form.StartPosition = [System.Windows.Forms.FormStartPosition]::CenterScreen

	$null = New-Label $Form "Easy NetScaler Tool" 5 0 190 25 14 'bold'

	$VersionB = New-Button $Form "v$ScriptVersion" 260 0 50 20
	$VersionB.Add_Click({ Update-Script })

	$null = New-Label $Form "Username:" 5 30 75 20 10 'regular'
	$UserNameTB = New-TextBox $Form 80 30 150 20
	if ($Username) { $UserNameTB.Text = $UserName } else { $UserNameTB.Text = "nsroot" }

	$null = New-Label $Form "Password:" 5 55 75 20 10 'regular'
	$PasswordTB = New-TextBox $Form 80 55 150 20
	$PasswordTB.Text = "$Password"
	$PasswordTB.UseSystemPasswordChar = $true
	$ShowPwdB = New-Button $Form "Show" 235 55 50 20
	$ShowPwdB.Add_Click({ TogglePWD })

	$null = New-Label $Form "IP:" 5 80 75 20 10 'regular'
	$IPTB = New-TextBox $Form 80 80 150 20
	$IPTB.Text = $IP

	# Row 1: Backup operations
	$BackupB = New-Button $Form "Backup" 5 110 100 30
	$BackupB.Add_Click({ Backup-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$ConfigB = New-Button $Form "Config" 110 110 100 30
	$ConfigB.Add_Click({ Config-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$CleanB = New-Button $Form "Clean FS" 215 110 100 30
	$CleanB.Add_Click({ Clean-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	# Row 2: Upgrade operations
	$UpgradeB = New-Button $Form "Upgrade" 5 145 100 30
	$UpgradeB.Add_Click({ Upgrade-NS -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$PlanUpgradeB = New-Button $Form "Plan Upgrade" 110 145 100 30
	$PlanUpgradeB.Add_Click({ PlanUpgrade -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$DownloadB = New-Button $Form "Download FW" 215 145 100 30
	$DownloadB.Add_Click({ Start "https://www.citrix.com/downloads/citrix-adc/" })

	# Row 3: Failover operations
	$FailoverB = New-Button $Form "Failover NOW" 5 180 100 30
	$FailoverB.Add_Click({ Failover -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$PlanFailoverB = New-Button $Form "Plan Failover" 110 180 100 30
	$PlanFailoverB.Add_Click({ PlanFailover -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$HAB = New-Button $Form "HA Status" 215 180 100 30
	$HAB.Add_Click({ HAStatus -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	# Row 4: Status and reports
	$VerB = New-Button $Form "Version" 5 215 100 30
	$VerB.Add_Click({ Version -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$vServerReportB = New-Button $Form "vServer Report" 110 215 100 30
	$vServerReportB.Add_Click({ Export-vServerReport -U $UsernameTB.Text -P $PasswordTB.Text -IP $IPTB.Text })

	$CompareB = New-Button $Form "Compare" 215 215 100 30
	$CompareB.Add_Click({ Show-CompareDialog })

	$null = $Form.ShowDialog()
}

del $putty, $pscp -EA 0