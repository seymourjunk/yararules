private global rule IsPe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

private rule PEB
{
    strings:
        $peb_x86 = {64 A1 30 00 00 00}              // mov eax, fs:[0x30]
        $peb_x64 = {65 48 8B 04 25 60 00 00 00 }    // mov rax,qword ptr gs:[0x60]
    condition:
        1 of ($peb*)
}

rule NtGlobalFlag : antidbg
{
    meta:
        arch = "Windows"
        description = "Detect getting offset from a PEB-structure to some specific field"
    strings:
        $NtGlobalFlag_x86 = {8b (48 | 40 | 58) 68}              // mov <reg>, dword ptr [eax+0x68]
        $NtGlobalFlag_x64 = {8b (88 | 80 | 98) bc 00 00 00}     // mov <reg>, dword ptr [rax+0xbc]
        $op1 = {f6 80 bc 00 00 00 70}                           // test byte ptr [eax+0xbc],0x70
        $op2 = {83 E? 70}                                       // add (sub) eax, 0x70

    condition:
        PEB and ((1 of ($NtGlobalFlag*)) or (1 of ($op*)))
}

rule DbgCheck_WinApi : antidbg
{
    meta:
        arch = "Windows"
        description = "Detect debugger via WinApi functions"
    strings:
        $s1 = "QuerySystemInformation"
		$s2 = "QueryInformationProcess"
        $s3 = "CheckRemoteDebuggerPresent"
		$s4 = "SetInformationThread"
		$s5 = "DebugActiveProcess"
        $s6 = "RtlQueryProcessHeapInformation"
        $s7 = "GetTickCount"
        $s8 = "OutputDebugString"
    condition:
        any of them
}

rule TrapFlag
{
    meta:
        arch = "Windows"
        descriptions = "Setting TF for debugger detect (see exception handling)"
        notes = "for x86 only"
    strings:
        $op = {9c 81 0c 24 00 01 00 00 9d 90}
    condition:
        any of them
}


/*
import "pe"
rule CheckImports
{
    condition:
        condition:
		pe.imports("kernel32.dll","CheckRemoteDebuggerPresent")
}
*/