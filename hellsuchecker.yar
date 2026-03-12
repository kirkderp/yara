/*
    HellsUchecker Backdoor + Delivery Chain YARA Rules
    Author: kirkderp
    Date: 2026-03-11
    Source: https://github.com/kirkderp/yara

    Covers:
      1. HellsUchecker native x64 backdoor (memory scan -- PE is never on disk)
      2. MSI dropper (on disk -- WiX-built, 2/76 VT as of 2026-03-11)
      3. MSBuild polyglot BAT (on disk -- BAT header + MSBuild XML + base91 payload)
      4. Shellcode loader (memory -- raw shellcode as injected by Hell's Gate)

    Named for the Hell's Gate syscall injection (stage 9a) + "uchecker" PDB path
    in the final PE. Kill chain: ClickFix -> finger.exe LOLBin -> Python -> MSI ->
    BAT/MSBuild -> .NET EtherHiding -> Hell's Gate shellcode injection -> uchecker backdoor

    Reference: https://derp.ca/blog/hellsuchecker-clickfix-etherhiding
*/

rule HellsUchecker_Backdoor
{
    meta:
        id = "XaKgn7Morr_pIPI_rOh_05"
        fingerprint = "549f157a1defdbefde0923a8cd73ed9dca028297e2f26074c0a0473915307d12"
        version = "1.0"
        date = "2026-03-11"
        modified = "2026-03-11"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "HellsUchecker native x64 backdoor - JSON-RPC HTTPS C2 with custom URL encoding. Memory-resident only (never written to disk). Scan process memory or dumps. PDB: uchecker.pdb."
        category = "MALWARE"
        malware = "HELLSUCHECKER"
        mitre_att = "T1071.001"
        reference = "https://derp.ca/blog/hellsuchecker-clickfix-etherhiding"
        triage_score = 10
        triage_description = "HellsUchecker backdoor detected in memory. Custom native x64 implant with JSON-RPC C2."

    strings:
        $pdb = "uchecker.pdb" ascii
        $jsonrpc_template = "{\"id\":,\"arguments\":[]}" ascii
        $ua_checkin = "myApp v1.0" ascii
        $ct_json = "Content-Type: application/json\r\n" ascii
        $fingerprint_prefix = "USERNAME=" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100KB
        and $pdb
        and $jsonrpc_template
        and 2 of ($ua_checkin, $ct_json, $fingerprint_prefix)
}

rule HellsUchecker_Backdoor_Wide
{
    meta:
        id = "V1kgj1znQLmaFSSdZ2PcEA"
        fingerprint = "f653285ece03301efc6e4fba4761387cb6af3b52acde1b288f557d8fac4070a8"
        version = "1.0"
        date = "2026-03-11"
        modified = "2026-03-11"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "HellsUchecker backdoor - broader detection without PDB path. Targets the unique combination of JSON-RPC template, custom User-Agent, and URL encoding pattern."
        category = "MALWARE"
        malware = "HELLSUCHECKER"
        mitre_att = "T1071.001"
        reference = "https://derp.ca/blog/hellsuchecker-clickfix-etherhiding"
        triage_score = 10
        triage_description = "Probable HellsUchecker backdoor detected. Custom JSON-RPC C2 implant."

    strings:
        $jsonrpc_template = "{\"id\":,\"arguments\":[]}" ascii
        $ua_checkin = "myApp v1.0" ascii
        $ct_json = "Content-Type: application/json\r\n" ascii
        $fingerprint_prefix = "USERNAME=" ascii
        $day_lut = "SunMonTueWedThuFriSat" ascii
        $month_lut = "JanFebMarAprMayJunJulAugSepOctNovDec" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize < 100KB
        and $jsonrpc_template
        and $ua_checkin
        and $ct_json
        and ($day_lut or $month_lut)
        and $fingerprint_prefix
}

rule HellsUchecker_MSI_Dropper
{
    meta:
        id = "7yYUKBsAG7h9MzsQlZbxze"
        fingerprint = "2ca7e864d2cdfad4bb2dfb2c98d6da02e6634502a40912ec8a03f2970f1d70cd"
        version = "1.0"
        date = "2026-03-11"
        modified = "2026-03-11"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "HellsUchecker MSI dropper - WiX-built installer masquerading as Microsoft Update. Drops BAT/MSBuild polyglot + VBS launcher to SvcUpdate directory."
        category = "MALWARE"
        malware = "HELLSUCHECKER"
        mitre_att = "T1218.007"
        reference = "https://derp.ca/blog/hellsuchecker-clickfix-etherhiding"
        triage_score = 10
        triage_description = "HellsUchecker MSI dropper detected. Fake Microsoft Update installer dropping BAT/MSBuild polyglot."

    strings:
        $install_dir = "SvcUpdate_" ascii wide
        $bat_name = "wscript_ce49" ascii wide
        $vbs_name = "wscript_29ab" ascii wide
        $cache_name = "runtime_75ef" ascii wide
        $fake_author = "Microsoft Update" ascii wide
        $product = "standalone_standard_configure" ascii wide

    condition:
        uint32(0) == 0xE011CFD0
        and filesize > 500KB
        and filesize < 5MB
        and $install_dir
        and ($bat_name or $vbs_name or $cache_name)
        and ($fake_author or $product)
}

rule HellsUchecker_MSBuild_Polyglot
{
    meta:
        id = "7HOcyNketAsPJBkLPs4PLr"
        fingerprint = "2454f4a4d7897ac24b7ea219c45b698fef0257df611ea1107e5d2bf1cfa7373d"
        version = "1.0"
        date = "2026-03-11"
        modified = "2026-03-11"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "HellsUchecker BAT/MSBuild polyglot - batch script header with embedded MSBuild XML project containing C# inline task. Base91-encoded .NET assembly payload between custom delimiters."
        category = "MALWARE"
        malware = "HELLSUCHECKER"
        mitre_att = "T1127.001"
        reference = "https://derp.ca/blog/hellsuchecker-clickfix-etherhiding"
        triage_score = 10
        triage_description = "HellsUchecker BAT/MSBuild polyglot detected. Batch script wrapping MSBuild inline C# task with base91-encoded payload."

    strings:
        $bat_header = "@echo off" ascii nocase
        $msbuild_project = "<Project" ascii
        $code_task_factory = "CodeTaskFactory" ascii
        $csharp_inline = "<Code Type=\"Class\" Language=\"cs\">" ascii
        $base91_delim = "::85a210c1::" ascii
        $task_class = "T_a84ee9c6" ascii

    condition:
        filesize > 1MB
        and filesize < 50MB
        and $bat_header in (0..100)
        and $msbuild_project
        and $code_task_factory
        and $csharp_inline
        and ($base91_delim or $task_class)
}

rule HellsUchecker_Shellcode_Loader
{
    meta:
        id = "ssI6NI2m8XL6s7Bj_50cli"
        fingerprint = "bb14f18efb80ed58ab1387945573d9d587f58e69e33431f3ff96f0034744569f"
        version = "1.0"
        date = "2026-03-11"
        modified = "2026-03-11"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "HellsUchecker x64 shellcode loader - position-independent code with SipHash-variant CTR cipher and aPLib decompression. Targets raw shellcode as injected via Hell's Gate NtCreateSection."
        category = "MALWARE"
        malware = "HELLSUCHECKER"
        mitre_att = "T1055.012"
        reference = "https://derp.ca/blog/hellsuchecker-clickfix-etherhiding"
        triage_score = 10
        triage_description = "HellsUchecker shellcode loader detected in memory. SipHash-CTR cipher + aPLib PE loader."

    strings:
        // Config token in unencrypted config area (offset 0x002E)
        $config_token = "ebAZZQH7n" ascii

        // Shellcode entry point: POP RCX; PUSH RBP; MOV RBP,RSP; AND RSP,-16; SUB RSP,0x20; CALL +5
        $entry_point = { 59 55 48 89 E5 48 83 E4 F0 48 83 EC 20 E8 05 00 00 00 }

        // SipHash-CTR round: ROL5, SHR27, ROL8, ROR16 rotation constant cluster
        $siphash_round = { C1 E0 05 C1 E9 1B ?? ?? ?? ?? ?? C1 E9 18 ?? ?? ?? ?? ?? C1 E0 08 }

        // aPLib decompressor prologue
        $aplib_prologue = { 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 4C 89 70 20 55 48 8B EC 48 83 EC 40 }

    condition:
        not uint16(0) == 0x5A4D
        and filesize < 100KB
        and $config_token
        and ($entry_point or $siphash_round or $aplib_prologue)
}
