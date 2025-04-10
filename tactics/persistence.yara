rule LogonAutostart
{
    meta:
        description = "Adding a program to a logon initialization"
    strings:
        $reg1 = "System\\CurrentControlSet\\Control\\Session Manager"   // BootExecute
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" nocase
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        $reg4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" nocase  // UserInit, Shell (explorer.exe)

        $reg5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg6 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg7 = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" nocase
        $reg9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" nocase

        $reg10 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" nocase
        $reg11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" nocase
        $reg12 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" nocase
    condition:
        any of them
}

rule RegistryExplorer
{
    meta:
        description = "Adding a modification for explorer.exe via Registry key"
    strings:
        $reg1 = "Software\\Classes\\Directory\\ShellEx\\" nocase
        $reg2 = "Software\\Classes\\*\\ShellEx\\ContextMenuHandlers" nocase
        $reg3 = "Software\\Classes\\Drive\\ShellEx\\ContextMenuHandlers" nocase
    condition:
        any of them
}