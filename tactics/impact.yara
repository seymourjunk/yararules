private rule IsPe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule VolumeShadowCopyDeletion
{
    meta:
        description = "Program can delete all volume shadow copies on a system to prevent recovery"
    strings:
        $exe1 = "vssadmin" ascii wide nocase
        $s1 = "delete shadows /all" ascii wide nocase
        $exe2 = "bcdedit" ascii wide nocase
        $s2 = "/set recoveryenabled no" ascii wide nocase
        $s3 = "bootstatuspolicy ignoreallfailures" ascii wide nocase
        $exe3 = "wmic" ascii wide nocase
        $s4 = "shadowcopy delete" ascii wide nocase
        $s5 = "shadowcopy /nointeractive" ascii wide nocase
        $exe4 = "wbadmin" ascii wide nocase
        $s6 = "delete catalog -quiet" ascii wide nocase
        $s7 = "diskshadow delete shadows all"
    condition:
        isPe and (1 of ($exe*)) and (1 of ($s*)))
}