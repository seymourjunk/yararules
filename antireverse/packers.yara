// name section like  Petite, WinUpack (UPack), Themida
import "pe"
import "math"

private global rule IsPe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule Entropy
{
    meta:
        description = "Files with an entropy above 7.2 tend to be malicious"
    condition:
        math.entropy(0, filesize) >= 7.2
}

rule AbnormalSectionSize
{
    meta:
        description = "The program has abnormal section sizes — section with a Size of Raw Data of 0 and Virtual Size of nonzero"
    condition:
        (for any i in (0..pe.number_of_sections-1): (
            pe.sections[i].raw_data_size == 0 and pe.sections[index].virtual_size > 0)
        )
}

rule SuspiciousNumberOfImports
{
    meta:
        description = "Just a few specific import (or without import at all), — packer?"
    condition:
        (pe.number_of_imported_functions < 4 and pe.imports("kernel32.dll", "LoadLibraryA") and pe.imports("kernel32.dll", "GetProcAddress"))
        or ((pe.number_of_imported_functions < 6) and pe.imports("kernel32.dll", "LoadLibrary") and pe.imports("kernel32.dll", "GetProcAddress") 
            and (pe.imports("kernel32.dll", "VirtualProtect") or (pe.imports("kernel32.dll", "VirtualAlloc"))))
        or (pe.number_of_imported_functions <= 2)
}

rule SaveRegistersAtEntryPoint
{
    meta:
        description = "Save the contents of the general-purpose registers onto the stack"
        notes = "slow rule because first we find ALL matches of $s1 and then execute a condition"
    strings:
        $op1 = { 60 } // pusha
    condition:
        $op1 at pe.entry_point
}

rule UPX
{
    meta:
        description = "Detect UPX section names"
    strings:
        $s1 = "UPX0"
        $s2 = "UPX1"
        $s3 = "UPX2"
        $s4 = "UPX!"
    condition:
        any of them
}

rule PECompact
{
    meta:
        description = "Detect PECompact section names"
    strings:
        $s1 = "pec1"
        $s2 = "pec2"
    condition:
        any of them
}

rule ASPack
{
    meta:
        description = "Detect ASPack section names"
    strings:
        $s1 = "aspack"
        $s2 = ".adata"
    condition:
        any of them
}

rule WinUpack
{
    meta:
        description = "Detect WinUpack opcodes at entrypoint"
    strings:
        $op1 = { BE B0 11 ?? ?? AD 50 FF 76 34 EB 7C 48 01} // mov esi, offset <off>
                                                            // lodsd
                                                            // push eax
                                                            // push dword ptr [esi+0x34]
                                                            // jmp
                                                            // data
    condition:
        $op1 at pe.entry_point
}

