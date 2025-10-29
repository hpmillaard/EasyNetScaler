# EasyNetScaler

This script has several options to backup, clean and upgrade your NetScaler. If no commandline options are given or you just run the script through the right click menu in explorer, the script will show a GUI.

Commandline examples:
Open the GUI: .\EasyNetScaler.ps1

Display GUI with prefilled values: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1

Create a full backup: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup

Create a ns.conf backup: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Config

Clean the NetScaler filesystem: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Clean

Upgrade the NetScaler with the firmware: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Firmware C:\Temp\Build-14.1-12.35_nc_64.tgz

Plan forced failover: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Failovertime "1-2-2025 18:00"

Backup, Clean the FileSystem and upgrade the NetScaler with the given firmware and plan the forced failover: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup -Clean -Firmware C:\Temp\Build-14.1-12.35_nc_64.tgz -Failovertime "1-2-2025 18:00"

Since 1.9 I've created an update function and button. If you click on the version, the script checks if there is a newer version and will update itself.

The GUI:

![EasyNetScaler.ps1 screenshot](https://github.com/hpmillaard/EasyNetScaler/blob/main/EasyNetScaler.png?raw=true)
