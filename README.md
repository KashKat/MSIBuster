# msiabuser - Post Exploitation
Abusing MSI Exec installer to force uninstallation of restricted applications where the uninstallation option requires a master password or other anti-tampering is configured. 

An exploit like this shouldn't be used as there are usually simpler means to disabling or modifying enterprise EDR agents. This technique also requires the EDR agents Windows Installer to be present on the system either through ccmcache or manually transferring to the victim machine, or leverage get-wmiobject to find the Product ID. Lastly, this is a post-exploitation method, and requires local admin / elevated privileges.

`msiexec.exe /fa <installer.msi|{product Id} /qa`

While the Windows Installer attempts to complete an installation repair, monitor the EDR agent processes and wait for them to be terminated and then kill the WMIExec.exe process before re-installation completes. Most applications will terminate any live processes and/or services before beginning installation. Killing MSIExec at this point in time will terminate any EDR processes and their child processes through the killall command. 

`killall /f /t /im msiexec.exe`

That's about it. 
Also find the more automated process for C#. Testing has been very limited and requires elevated privileges on a system where uninstallation or other EDR evasion techniques fall short such as firewall rules, modifying registry, modifying related dll's or other files that would fall into MITRE ATT&CK ID: T1562.001
