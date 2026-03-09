/*
    ECHidna Backdoor YARA Rules
    Author: kirkderp
    Date: 2026-03-09
    Source: https://github.com/kirkderp/yara

    Covers:
      1. ECHidna RAT core (standalone DLL or decompressed inner PE)
      2. ECHidna BoringSSL loader (wrapper DLL with compressed payload in overlay)
      3. ECHidna LNK delivery stager (rundll32 DLL sideload chain)

    Tested against 5 known builds:
      - desktop.ini.dll   ee8d649c362e75c7d545868c4e1473ebd8d087abf6f916354991d2048eb48025
      - ssl.dll            74aa2eedaa6594efa2075ea2f4617ed3206d228b8fae5fc54382630764bdb5ad
      - WebRCS_2.dll       14143e8d8b9e2537db4ee57d86dfd9150641f3c470c66f6d9811743ca0a50441
      - desktop_inner_pe   5fefc9753074906cd2c60b7d76ba3fcd8002b90cf8fa085bc351f6272951272b
      - ssl_inner_pe       330c736541aac59ad37cbf63b88993c0d96764baf1508603fd138cfd396825f7

    Reference: VB2025 — Sawabe & Koike (NTT Security Holdings)
*/

rule ECHidna_RAT
{
    meta:
        id = "CSu4wu3qHviulG2rMh6upJ"
        fingerprint = "3e75ca8f962b8589304bd5a1bf89c36ee58f90b32230b162c29701e1ae7fa8bf"
        version = "1.0"
        date = "2026-03-09"
        modified = "2026-03-09"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "ECHidna backdoor RAT core with custom Base64 encoding and DoH-based resolution."
        category = "MALWARE"
        malware = "ECHIDNA"
        mitre_att = "T1071.001"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "ECHidna backdoor RAT core detected."

    strings:
        // Custom shuffled Base64 table (64 bytes — unique to ECHidna)
        $custom_b64 = "cqWKroElukZpUd7X2FRJhAC3IS05j6efzDmaVwv4igGtTY89sOx1QHPNBMLybn+-" ascii

        // PDB project name
        $pdb = "WebRCS.pdb" ascii

        // C2 URL paths
        $c2_get = "/webrcs/index.php" ascii
        $c2_post = "/webrcs/upload.php" ascii

        // Host ID marker format (varies per build: 24508, 23830, etc.)
        $host_id = /[0-9]{4,5}ECH\(x86\)/ ascii

        // RAT commands (UTF-16LE in .rdata)
        $cmd_shell = "shell" wide
        $cmd_upload = "upload" wide
        $cmd_download = "download" wide
        $cmd_setting = "setting" wide

        // DoH resolver servers (7 known, require 3+ match)
        $doh1 = "dns.google.com" ascii
        $doh2 = "doh-2.seby.io" ascii
        $doh3 = "doh.dns.sb" ascii
        $doh4 = "dns.twnic.tw" ascii
        $doh5 = "doh-fi.blahdns.com" ascii
        $doh6 = "doh-jp.blahdns.com" ascii
        $doh7 = "dns.rubyfish.cn" ascii

        // Config persistence: hash seed and environment variable
        $config_env = "%ALLUSERSPROFILE%" wide
        $config_seed = { 00 00 CD AB }  // 0xABCD0000 LE

        // Build path fragment
        $build_path = "boringssl_x86\\build\\WebRCS" ascii

    condition:
        uint16(0) == 0x5a4d
        and filesize > 500KB and filesize < 2MB
        and (
            $custom_b64
            or ($pdb and ($c2_get or $c2_post))
            or ($host_id and 3 of ($cmd_*))
            or ($c2_get and $c2_post and 3 of ($doh*))
            or ($config_env and $config_seed and ($pdb or $c2_get or $c2_post))
            or ($build_path and ($c2_get or $c2_post))
        )
}

rule ECHidna_Loader
{
    meta:
        id = "2Z3cMJ7JbX5NRIoKRSUiHq"
        fingerprint = "40a46a11cdeca6df9df8d5707512cc71d40c77aed9f7f021d36738d8bf692f98"
        version = "1.0"
        date = "2026-03-09"
        modified = "2026-03-09"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "ECHidna BoringSSL wrapper DLL with compressed RAT payload in PE overlay."
        category = "MALWARE"
        malware = "ECHIDNA"
        mitre_att = "T1027.009"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "ECHidna BoringSSL loader with embedded payload detected."

    strings:
        // Overlay markers followed by reflective loader shellcode (push 0, call, ret, int3 padding)
        $overlay_bfbf = { BF BF BF BF 6A 00 E8 09 00 00 00 C3 CC CC CC CC }
        $overlay_dadd = { BF AD DD DA 6A 00 E8 09 00 00 00 C3 CC CC CC CC }

        // Build path unique to WebRCS project (in BoringSSL assert messages)
        $build_webrcs = "boringssl_x86\\build\\WebRCS" ascii

        // C2 path survives LZ77 compression in overlay
        $c2_path = "/webrcs/" ascii

        // Host ID in compressed overlay
        $host_id = /[0-9]{4,5}ECH\(x86\)/ ascii

        // SSL_version export used as DLL entry point
        $export_ssl = "SSL_version" ascii

    condition:
        uint16(0) == 0x5a4d
        and filesize > 1MB and filesize < 3MB
        and (
            ($overlay_bfbf or $overlay_dadd)
            or ($build_webrcs and ($c2_path or $host_id))
            or ($export_ssl and $c2_path and $build_webrcs)
        )
}

rule ECHidna_Delivery_LNK
{
    meta:
        id = "uapjdWLMJKm7q5p5G1fb2w"
        fingerprint = "37479c9b5af3550ab9e30b9a67d93b1749c79ff7e6bcfcf692a09542763161b9"
        version = "1.0"
        date = "2026-03-09"
        modified = "2026-03-09"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "ECHidna LNK delivery stager that sideloads the BoringSSL wrapper via rundll32."
        category = "MALWARE"
        malware = "ECHIDNA"
        mitre_att = "T1204.002"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "ECHidna LNK delivery stager detected."

    strings:
        // DLL filename pattern used for staging
        $ms_service = "MS-Service" wide

        // SSL_version export name passed to rundll32
        $ssl_version = "SSL_version" wide

        // desktop.ini used as disguised DLL source
        $desktop_ini = "desktop.ini" wide

        // ExecutionPolicy bypass string evasion (splits "bypass")
        $bypass_evasion = "by+pass" wide

        // Secondary C2 tracking beacon
        $tracking = "jlmin.cc" wide

    condition:
        uint32(0) == 0x0000004c  // LNK magic
        and filesize < 10KB
        and (
            ($ms_service and $ssl_version)
            or ($desktop_ini and $ssl_version)
            or ($bypass_evasion and ($ms_service or $ssl_version))
            or ($tracking and $desktop_ini)
        )
}
