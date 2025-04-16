# MSI Buster (buster) - Post Exploitation
Abusing Microsoft Installer (MSIexec) to force repair a hardened EDR where the uninstallation option requires an uninstallation password, and other anti-tampering is configured. This also requires that the .msi software package is present on the end-point, either uploaded manually or discoverable in SCCM/MECM cache directories. 

## Exploitation
For when post exploitation still requires disabling the EDR agent on an end point, but the usual low hanging fruit are gatekeeped by anti-tampering configurations limiting access to processes, services, installation directory, integrity checks or registry (sub)keys. The EDR agents I've researched is often safeguarded by an intended uninstallation through msiexec.exe with a password, however this does not always apply to the forced repair '`/fa`' argument. 

The attack involves locating the cached MSI installer for the EDR agent, then invoking a forced repair process using msiexec /fa. 

`msiexec.exe /fa <installer.msi|{product Id} /qa`

During the repair process, the EDR agent and its child processes are momentarily terminated, creating a narrow but exploitable window. By forcefully terminating the repair process (MSIExec) mid-execution, but after the EDR has been shut down and just before it is reinitialized, the EDR remains non-functional.

`killall /f /t /im msiexec.exe`

This allows a red-team operator or threat actor to bypass detection and execute payloads without triggering the EDR's monitoring capabilities. 

Can automate the process with the EDRBuster.cs and compile it. 

## Other Info
Testing has been very limited, most environments will require elevated privileges (high integrity). 
Working to find better indicators to make EDR Agent inoperable upon system restart. 

MITRE ATT&CK ID: T1562.001
