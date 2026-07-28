/*
  C2 / SIGNAL local NocturneLdr triage rules.
  Nocturne is a Windows x64 shellcode loader that injects code into a
  sacrificial DLL's .text section and registers a forged RUNTIME_FUNCTION
  to defeat CET-compatible stack walks (BYOUD). It also chains EAF bypass,
  RtlRegisterWait-based sleep obfuscation (Zilean) and heap masking.

  These rules identify stable static artifacts and technique families.
  They are indicators for analyst review, not proof of compromise.

  References
    https://github.com/klezVirus/BYOUD
    https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
*/

import "math"
import "pe"

rule C2SIGNAL_NocturneLdr_Sample_HighConfidence
{
    meta:
        description = "NocturneLdr static artifacts: XOR key or cipher header or sacrificial DLL literal"
        author = "C2 / SIGNAL"
        severity = "critical"
        category = "nocturneldr-loader"

    strings:
        // XOR key from Main.cpp::XorKey[] (default build)
        $xor_key = {
            37 B6 7C B2 91 5A 49 9F 1A 19 77 37 6F 87 E0 0A
            7E 46 11 61 56 B6 70 27 97 2E CA 60 0D 8F 22 FE
        }

        // First 16 bytes of default msfvenom ciphertext in Main.cpp
        $cipher = {
            CB FE FF 56 61 B2 89 9F 1A 19 36 66 2E D7 B2 5B
            28 0E 20 B3 33 FE FB 75 F7 66 41 32 15 C7 A9 AC
        }

        // Sacrificial DLL literal from StackSpoofing.cpp::DllName[]
        $sacrificial_w = "windows.storage.dll" wide
        $sacrificial_a = "windows.storage.dll" ascii

    condition:
        filesize < 5MB and 2 of them
}

rule C2SIGNAL_NocturneLdr_EAFBypass_ShieldedRead
{
    meta:
        description = "ShieldedRead tail-call dispatch into EAF-bypass gadget"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "nocturneldr-eafbypass"
        technique = "T1562.001"

    strings:
        // Unguard.asm::ShieldedRead: test rdx,rdx ; jz ; mov rax,rcx ; jmp rdx
        $shield_dispatch = { 48 85 D2 74 ?? 48 89 C8 FF E2 }
        // Target gadget body: mov rax,[rax] ; ret
        $gadget_body     = { 48 8B 00 C3 }

    condition:
        filesize < 5MB and $shield_dispatch and $gadget_body
}

rule C2SIGNAL_NocturneLdr_BYOUD_DynamicFunctionTableWalk
{
    meta:
        description = "BYOUD head/sentinel triple pattern in RtlAddFunctionTable prologue"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "nocturneldr-byoud"
        technique = "T1055"

    strings:
        // 48 8B 05 = mov rax, [rip+disp32]
        $mov_head     = { 48 8B 05 }
        // 48 8D 0D = lea rcx, [rip+disp32]
        $lea_sentinel = { 48 8D 0D }
        // 48 39 08 = cmp [rax], rcx
        $cmp_sentinel = { 48 39 08 }

    condition:
        filesize < 5MB and
        for any i in (1..#mov_head) : (
            for any j in (1..#lea_sentinel) : (
                for any k in (1..#cmp_sentinel) : (
                    (j > i) and (k > j) and (k - i < 48)
                )
            )
        )
}

rule C2SIGNAL_NocturneLdr_SleepObfuscation_ROPChain
{
    meta:
        description = "RtlRegisterWait + NtContinue sleep-obfuscation ROP chain setup"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "nocturneldr-zilean"
        technique = "T1497"

    strings:
        // CONTEXT_ALL = 0x0010000B
        $ctx_all = { B8 0B 00 10 00 }

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        $ctx_all
}

rule C2SIGNAL_NocturneLdr_HeapMasking_HeapWalk
{
    meta:
        description = "HeapWalk + per-cycle XOR heap masking (Zilean::MaskHeap)"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "nocturneldr-zilean"
        technique = "T1027.010"

    strings:
        // call HeapWalk ; test eax,eax ; jz ...
        $heap_walk_loop = { E8 ?? ?? ?? ?? 85 C0 74 ?? }
        // rdrand eax instruction
        $rdrand         = { 0F C7 F0 }

    condition:
        filesize < 5MB and $heap_walk_loop and $rdrand
}

rule C2SIGNAL_NocturneLdr_DJB2_CompileTimeHashResolver
{
    meta:
        description = "DJB2-with-7-shift compile-time API hash resolver (Primitives.h)"
        author = "C2 / SIGNAL"
        severity = "medium"
        category = "nocturneldr-resolver"
        technique = "T1027.007"

    strings:
        // Initial hash 5448 = 0x00001538
        $hinit   = { 38 15 00 00 }
        // shl reg, 7
        $shift7  = { C1 E? 07 }
        // xor reg, 0x1337
        $xor_key = { 81 F? 37 13 00 00 }

    condition:
        filesize < 5MB and
        for any i in (1..#hinit) : (
            for any j in (1..#shift7) : (
                for any k in (1..#xor_key) : (
                    math.abs(i - j) < 256 and math.abs(j - k) < 256
                )
            )
        )
}

rule C2SIGNAL_NocturneLdr_IATCamouflage_USER32Only
{
    meta:
        description = "IAT populated exclusively with USER32 GUI-noise APIs (IatCamouflage.h)"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "nocturneldr-camouflage"
        technique = "T1027.007"

    strings:
        $api_msgbox       = "MessageBoxA"             ascii
        $api_setcrit      = "SetCriticalSectionSpinCount" ascii
        $api_getwinhelp   = "GetWindowContextHelpId"  ascii
        $api_getwinlong   = "GetWindowLongPtrW"       ascii
        $api_regclass     = "RegisterClassW"          ascii
        $api_iswinvisible = "IsWindowVisible"         ascii
        $api_convertloc   = "ConvertDefaultLocale"    ascii
        $api_multibyte    = "MultiByteToWideChar"     ascii
        $api_isdlgmsg     = "IsDialogMessageW"        ascii

    condition:
        uint16(0) == 0x5A4D and
        filesize < 5MB and
        7 of ($api_*) and
        pe.number_of_imports > 0 and
        pe.number_of_imports <= 10 and
        for all detail in pe.import_details : (
            detail.library_name == "USER32.dll"
        )
}

rule C2SIGNAL_NocturneLdr_Family_Master
{
    meta:
        description = "NocturneLdr family-level master detection"
        author = "C2 / SIGNAL"
        severity = "critical"
        category = "nocturneldr-loader"
        technique = "T1027,T1055,T1574,T1497"

    condition:
        C2SIGNAL_NocturneLdr_Sample_HighConfidence
        or C2SIGNAL_NocturneLdr_EAFBypass_ShieldedRead
        or C2SIGNAL_NocturneLdr_BYOUD_DynamicFunctionTableWalk
        or C2SIGNAL_NocturneLdr_SleepObfuscation_ROPChain
        or ( C2SIGNAL_NocturneLdr_IATCamouflage_USER32Only
             and C2SIGNAL_NocturneLdr_HeapMasking_HeapWalk )
}
