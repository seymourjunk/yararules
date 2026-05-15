rule DisableTools
{
    meta:
        description = "Disable endpoint detection and response (EDR) tools"
    strings:
        $cmd1 = "Stop-Process -Name" ascii wide nocase
        $cmd2 = "Stop-Process -Force -Name" ascii wide nocase
        $cmd3 = "taskkill /IM" ascii wide nocase

        $n1 = "MsMpEng" ascii wide nocase
    condition:
        any of ($cmd*) and any of ($n*)
}