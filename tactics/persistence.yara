rule LogonAutostart
{
    meta:
        description = "Adding a program to a logon initialization"
    strings:
        $reg1 = "System\\CurrentControlSet\\Control\\Session Manager" wide ascii nocase  // BootExecute
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices" wide ascii nocase
        $reg3 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" wide ascii nocase
        $reg4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide ascii nocase  // UserInit, Shell (explorer.exe)

        $reg5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii nocase
        $reg6 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide ascii nocase
        $reg7 = "Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run" wide ascii nocase
        $reg8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide ascii nocase
        $reg9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Shell Folders" wide ascii nocase

        $reg10 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServicesOnce" wide ascii nocase
        $reg11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run" wide ascii nocase
        $reg12 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows" wide ascii nocase
    condition:
        any of them // will trigger even legitimate software installer, other criteria need to be clarified
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