# EasyNetScaler

This script has several options to backup, clean and upgrade your NetScaler. If no commandline options are given or you just run the script through the right click menu in explorer, the script will show a GUI.

Commandline examples:
Open the GUI: .\EasyNetScaler.ps1

Display GUI with prefilled values: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1

Create a full backup: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup

Create a ns.conf backup: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Config

Clean the NetScaler filesystem: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Clean

Upgrade the NetScaler with the firmware: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Firmware C:\Temp\Build-14.1-8.50_nc_64.tgz

Backup, Clean the FileSystem and upgrade the NetScaler with the firmware: .\EasyNetScaler.ps1 -Username nsroot -Password nsroot -IP 192.168.1.1 -Backup -Clean -Firmware C:\Temp\Build-14.1-8.50_nc_64.tgz

The GUI:

![EasyNetScaler.ps1 screenshot](https://github.com/hpmillaard/EasyNetScaler/blob/main/EasyNetScaler.gif?raw=true)
