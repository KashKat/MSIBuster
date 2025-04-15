# MSI Buster (buster) - Post Exploitation
Abusing Microsoft Installer - MSIexec to force repair a hardened applications where the uninstallation option requires an uninstallation password or other anti-tampering is configured. This also requires that the .msi software package is present on the end-point, either uploaded manually or discoverable in SCCM/MECM cache directories. 

## Exploitation
For when post exploitation still requires disabling the EDR agent on an end point, but the usual low hanging fruit are gatekeeped by anti-tampering configurations limiting access to processes, services, installation directory or registry (sub)keys. The EDR agents I've researched is often safeguarded by an uninstallation command through msiexec.exe with a password, however this doesn't always apply to the forced repair '`/fa`' argument. 

`msiexec.exe /fa <installer.msi|{product Id} /qa`

While the Microsoft Installer (MSIExec) begins the process of the repair, the EDR agent process(es) will be terminated and services shutdown in order to modify all files in the installation directory. Monitoring for this process shutdown manually through task manager, then end the process associated to msiexec.exe with the `killall` command.  

`killall /f /t /im msiexec.exe`

The EDR Agent process(es) are terminated and considered inoperable until the system is restarted. 
Can automate the process with the EDRBuster.cs and compile it. 

## Other Info
Testing has been very limited, most environments will require elevated privileges (high integrity). 
Working to find better indicators to make EDR Agent inoperable upon system restart. 

MITRE ATT&CK ID: T1562.001
