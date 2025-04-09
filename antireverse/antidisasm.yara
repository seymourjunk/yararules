rule SEH_Init
{
    meta:
        description = "Misusing Structured Exception Handlers"
    strings:
        $op1 = {64 ff 35 00 00 00 00}   // push dword ptr fs:0x0
        $op2 = {64 89 25 00 00 00 00}   // mov dword ptr fs:0x0, esp
    condition:
        all of them
}