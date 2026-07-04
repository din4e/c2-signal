/*
  C2 / SIGNAL local Cobalt Strike triage rules.
  These rules identify stable Beacon/BOF artifacts and decoded configuration
  blocks. They are indicators for analyst review, not proof of compromise.
*/

rule C2SIGNAL_CS_Beacon_Decoded_Config
{
    meta:
        description = "Cobalt Strike Beacon decoded configuration structure"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "cobalt-strike-beacon"

    strings:
        $config_header = { 00 01 00 01 00 02 00 01 00 02 00 02 00 01 00 ?? 00 03 00 02 00 04 }

    condition:
        filesize < 16777216 and $config_header
}

rule C2SIGNAL_CS_BOF_API_Surface
{
    meta:
        description = "Cobalt Strike Beacon Object File API imports"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "cobalt-strike-bof"

    strings:
        $api1 = "BeaconDataParse" ascii fullword
        $api2 = "BeaconDataExtract" ascii fullword
        $api3 = "BeaconFormatAlloc" ascii fullword
        $api4 = "BeaconFormatPrintf" ascii fullword
        $api5 = "BeaconOutput" ascii fullword
        $api6 = "BeaconPrintf" ascii fullword

    condition:
        filesize < 5242880 and 2 of them
}

rule C2SIGNAL_CS_Beacon_Core_Artifact
{
    meta:
        description = "Cobalt Strike Beacon core PE string constellation"
        author = "C2 / SIGNAL"
        severity = "high"
        category = "cobalt-strike-beacon"

    strings:
        $s1 = "%02d/%02d/%02d %02d:%02d:%02d" ascii
        $s2 = "%s as %s\\%s: %d" ascii
        $s3 = "Started service %s on %s" ascii
        $s4 = "beacon.dll" ascii fullword
        $s5 = "beacon.x64.dll" ascii fullword
        $s6 = "ReflectiveLoader" ascii fullword
        $s7 = "Content-Type: application/octet-stream" ascii

    condition:
        uint16(0) == 0x5a4d and filesize < 5242880 and 4 of them
}
