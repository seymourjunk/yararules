rule InputCaptureKeylogging
{
    meta:
        description = "Methods of capturing user input to obtain credentials or collect information"
    strings:
        // Keylogger APIs
        $api1 = "SetWindowsHookEx" ascii wide
        $api2 = "GetAsyncKeyState" ascii wide
        $api3 = "GetKeyState" ascii wide
        $api4 = "MapVirtualKeyA" ascii wide
        $api5 = "GetKeyboardState" ascii wide
        $api6 = "GetForegroundWindow" ascii wide
        
        // Delete browser cookies to force users to re-login
        $path1 = "Google\\Chrome\\User Data\\Default\\Network\\Cookies" ascii wide nocase
        $path2 = "Mozilla\\Firefox\\Profiles" ascii wide nocase
        $path3 = "Microsoft\\Edge\\User Data\\Default\\Network\\Cookies" ascii wide nocase

condition:
    (uint16(0) == 0x5A4D) and 2 of ($api*) or (1 of ($api*) and any of ($path*))
}