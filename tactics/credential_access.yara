rule OSCredentialDumping
{
    meta:
        description = "Attempt to access credential material stored in the process memory of the LSASS"
    strings:
        $cmd1 = "procdump" ascii wide nocase
        $cmd2 = "comsvcs.dll" ascii wide nocase
        $cmd3 = "werfault.exe" ascii wide nocase
        $cmd4 = "minidump" ascii wide nocase
        $cmd5 = "mimikatz" ascii wide nocase
        $cmd6 = "sekurlsa::logonPasswords" ascii wide nocase

        // default folder to store dump from werfault.exe
        $p1 = "AppData\\Local\\Microsoft\\Windows\\WER" ascii nocase wide 

        // Windows Security Support Provider (SSP) DLLs are loaded into LSASS process at system start. The SSP configuration is stored in two registry keys.
        $reg1 = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\Security Packages" ascii wide nocase
        $reg2 = "SYSTEM\\CurrentControlSet\\Control\\Lsa\\OSConfig\\Security Packages" ascii wide nocase

        // A non-privileged or abnormal process attempts to open a handle with full access (0x1F0FFF) to lsass.exe and subsequently invokes memory dump, file creation, or registry modification indicative of credential scraping
        $api1 = "OpenProcess"
        $api2 = "0x1f0fff"
        $api3 = "0x1fffff"
condition:
    (uint16(0) == 0x5A4D) and ((1 of ($cmd*)) or $p1 or (1 of ($reg*)) or (2 of ($api*)))
}