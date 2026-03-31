/*
    ClickFix / SERPENTINE#CLOUD YARA Rules
    Author: kirkderp
    Date: 2026-03-31
    Source: https://github.com/kirkderp/yara

    Covers:
      1. Kramer Python bytecode obfuscator (pyc with .py extension)
      2. VenomRAT v3.6 (dcRAT/qwqdanchun fork) .NET payload
      3. AsyncRAT 0.5.7B .NET payload
      4. XWorm / Violet v5 .NET payload
      5. PureHVNC (PureCoder) .NET DLL stage2
      6. Brute Ratel C4 loader (native x64 PE)

    Tested against 17 known samples:
      - 1MAR30_Annnnnnnnnnnnn-obf.py    (Kramer pyc, MA set)
      - 1MAR30_Asssssssssssssss-obf.py   (Kramer pyc, MA set)
      - 1MAR30_Hvvvvvvvvvvvv-obf.py      (Kramer pyc, MA set)
      - 1MAR30_UK-Viooooooooo-obf.py     (Kramer pyc, MA set)
      - 2LazMAR30_hvvvvvvvvvvvvvvvv.py   (Kramer pyc, MA set)
      - 1SMAR30_Annnnnn-obf.py           (Kramer pyc, ST set)
      - 1SMAR30_Asssssssssssssssssssss-obf.py  (Kramer pyc, ST set)
      - 1SMAR30_Hvvvvvvvvvvvvvvvvvvv-obf.py    (Kramer pyc, ST set)
      - 1SMAR30_UK-Vioooooooooooooooo-obf.py    (Kramer pyc, ST set)
      - 2SLazMAR30_hvvvvvvvvvvvvvvvvv.py         (Kramer pyc, ST set)
      - mod_Ann_shellcode.bin  58d9f039ec38bbe03a1e1bf58a0102ce9c94d6efe39d2450cb44917d4a5c75af
      - mod_Ass_shellcode.bin  4bb4a303b8e4873401be1cea68d50bdaa454471685dc30ad61e9ef746181aa29
      - mod_Vio_shellcode.bin  8cda591f526a09954c7a60337daa767be7948367ee52accebc30061be1dc581a
      - Hvv_stage2.bin         59079dbdfb0346deae4efc361d78844141bf77d916adec96b23d8061e20e123c
      - mod_2LazMAR30_shellcode.bin  026f71d40fa2e3c530283c1a70925d14eeee18d98f95506dd88cb698ccca6859
*/

rule Kramer_PYC_Obfuscator
{
    meta:
        id = "r68QjRG1X42Zqal0mtOs85"
        fingerprint = "c107955cdfa413d14cdcb1d4bd5971352f2bc5db4bf5465a804621049446464e"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Kramer Python bytecode obfuscator used by SERPENTINE#CLOUD -- encodes source via CJK Unicode offsets, eval at runtime"
        category = "MALWARE"
        malware = "KRAMER"
        mitre_att = "T1027.013"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Kramer Python bytecode obfuscator detected."
        yarahub_uuid = "79adf976-9d41-4e2d-a2b3-0a4e340951e5"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "c923a78e3d3da6be010578dbd7c126d1"

    strings:
        // Kramer class name in bytecode string table
        $class_name = "Kramer" ascii

        // Decode method qualified name
        $decode_method = "Kramer.__decode__" ascii

        // Init method qualified name
        $init_method = "Kramer.__init__" ascii

        // Lambda in init (Kramer-specific nested decode logic)
        $init_lambda = "Kramer.__init__.<locals>.<lambda>" ascii

        // Instance attribute names stored in bytecode co_names
        $attr_encode = "_encode" ascii
        $attr_bits = "_bits" ascii
        $attr_sparkle = "_sparkle" ascii

    condition:
        // Python 3.12 pyc magic (cb 0d 0d 0a little-endian)
        uint32(0) == 0x0A0D0DCB
        and filesize > 500KB and filesize < 20MB
        and $class_name
        and $decode_method
        and $init_method
        and $init_lambda
        and 2 of ($attr_encode, $attr_bits, $attr_sparkle)
}

rule VenomRAT_v36
{
    meta:
        id = "Cpu4cELWET4LHVKv8Kznwi"
        fingerprint = "c9dff9fdd0b06e593081f383d934dc57c00ab2390ac29f6065e2800b91732b64"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "VenomRAT v3.6 (dcRAT/qwqdanchun fork) -- AMSI/ETW bypass, plugin loader, process kill list"
        category = "MALWARE"
        malware = "VENOMRAT"
        mitre_att = "T1219"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "VenomRAT v3.6 dcRAT fork detected."
        yarahub_uuid = "4719b9d9-7ea5-4c2f-8dab-61620ea50f4a"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "a1dfce8e37a7f1a4ef5c722049521352"

    strings:
        // VenomRAT-specific underscore command names (differ from AsyncRAT)
        $cmd_plugin = "plu_gin" ascii wide
        $cmd_save = "save_Plugin" ascii wide

        // dcRAT lineage -- TLS cert issuer baked into all builds
        $dcrat_salt = "DcRatByqwqdanchun" ascii wide

        // AMSI bypass target
        $amsi = "AmsiScanBuffer" ascii wide

        // ETW bypass target
        $etw = "EtwEventWrite" ascii wide

        // Anti-analysis class name unique to this builder
        $anti = "Anti_Analysis" ascii wide

        // Settings field names with underscores (VenomRAT-specific naming)
        $cfg_ports = "Por_ts" ascii wide
        $cfg_hosts = "Hos_ts" ascii wide

        // Obfuscated class name unique to this build
        $class_meth = "Mesth4ods" ascii wide

        // Process kill list targeting security tools
        $kill_ph = "ProcessHacker" ascii wide
        $kill_mpux = "MpUXSrv" ascii wide
        $kill_csp = "ConfigSecurityPolicy" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 30KB and filesize < 500KB
        and $dcrat_salt
        and ($cmd_plugin or $cmd_save)
        and ($amsi or $etw)
        and 2 of ($cfg_ports, $cfg_hosts, $class_meth, $anti)
        and 1 of ($kill_ph, $kill_mpux, $kill_csp)
}

rule AsyncRAT_057B
{
    meta:
        id = "4j2WP1mJD3cNE60ZyHsOgC"
        fingerprint = "efcb736b80c4dfc515395045c34a26a46274fec546dd80d571b8dbc090180f71"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "AsyncRAT 0.5.7B -- minimal .NET RAT with PBKDF2 key derivation and MessagePack serialization"
        category = "MALWARE"
        malware = "ASYNCRAT"
        mitre_att = "T1219"

        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "AsyncRAT 0.5.7B .NET payload detected."
        yarahub_uuid = "2f0773d9-650c-4444-b237-0bd105d94994"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "addb2f9bc9ffad336cbee648fdfcf138"

    strings:
        // Canonical AsyncRAT PBKDF2 salt -- 32 raw bytes embedded in .NET resource
        // bfeb1e56fbcd973bb219022430a57843003d5644d21e62b9d4f180e7e6c33941
        $salt = { bf eb 1e 56 fb cd 97 3b b2 19 02 24 30 a5 78 43 00 3d 56 44 d2 1e 62 b9 d4 f1 80 e7 e6 c3 39 41 }

        // Client namespace
        $ns_handle = "Handle_Packet" ascii

        // Command strings (no underscore, unlike VenomRAT)
        $cmd_save = "savePlugin" ascii wide
        $cmd_pong = "pong" ascii wide

        // TLS cert field name (differs from VenomRAT's Server_Certificate)
        $cert_field = "ServerCertificate" ascii

        // MessagePack serialization library
        $msgpack = "MessagePackLib" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 20KB and filesize < 500KB
        and $salt
        and $ns_handle
        and ($cmd_save or $cmd_pong)
        and ($cert_field or $msgpack)
}

rule XWorm_Violet_v5
{
    meta:
        id = "7AXQEJIq4084eHO9b1OQcK"
        fingerprint = "6d279e229932392323fef344c12c921620e5e7db573d3b3b1f00861ff55e2e1b"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "XWorm / Violet v5 -- 80+ command RAT with HVNC, keylogger, crypto clipper, USB worm, webcam capture"
        category = "MALWARE"
        malware = "XWORM"
        mitre_att = "T1219"

        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "XWorm Violet v5 RAT detected."
        yarahub_uuid = "74ba7289-0235-4623-bae1-1a96abe95c18"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "403f1a3b591c6da42efd290ec3094cdd"

    strings:
        // Drop filename stored as base64 in binary (UTF-16LE)
        // WinSc32.exe
        $drop_name = "WinSc32" ascii wide

        // Cleanup bat stored as base64 -> decoded, also present as UTF-16LE
        // WinTempClean32.bat -> base64 V2luVGVtcENsZWFuMzIuYmF0
        $cleanup_b64 = "V2luVGVtcENsZWFuMzIuYmF0" ascii wide

        // Webcam capture via avicap32.dll
        $webcam_api = "capCreateCaptureWindowA" ascii

        // HVNC desktop switching
        $hvnc_api = "OpenInputDesktop" ascii

        // Version string base64: Violet v5 -> VmlvbGV0IHY1
        $version_b64 = "VmlvbGV0IHY1" ascii wide

        // C2 protocol separator base64: XSXSXSX -> WFNYU1hTWA==
        $sep_b64 = "WFNYU1hTWA" ascii wide

        // Base64 of mutex HOHE6S8FaZZlGf0f -> SE9IRTZTOEZhWlpsR2YwZg==
        $mutex_b64 = "SE9IRTZTOEZhWlpsR2YwZg" ascii wide

        // Update screen commands (base64 encoded)
        // ShowUpdateScreen -> U2hvd1VwZGF0ZVNjcmVlbg==
        $show_update_b64 = "U2hvd1VwZGF0ZVNjcmVlbg" ascii wide
        // HideUpdateScreen -> SGlkZVVwZGF0ZVNjcmVlbg==
        $hide_update_b64 = "SGlkZVVwZGF0ZVNjcmVlbg" ascii wide

        // SERPENTINE#CLOUD cross-campaign GUID (same in 02192026 and 03312026)
        // 3d847c5c-4f5a-4918-9e07-a96cea49048d -> base64 M2Q4NDdjNWMtNGY1YS00OTE4LTllMDctYTk2Y2VhNDkwNDhk
        $guid_b64 = "M2Q4NDdjNWMtNGY1YS00OTE4LTllMDctYTk2Y2VhNDkwNDhk" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 30KB and filesize < 500KB
        and (
            // Tier 1: cross-campaign GUID (unique to this operator)
            $guid_b64
            or (
                // Tier 2: Violet version + protocol separator
                $version_b64 and $sep_b64
            )
            or (
                // Tier 3: behavioral combination -- drop artifacts + HVNC + webcam
                ($drop_name or $cleanup_b64)
                and ($webcam_api or $hvnc_api)
                and 2 of ($show_update_b64, $hide_update_b64, $mutex_b64, $sep_b64)
            )
        )
}

rule PureHVNC_PureCoder
{
    meta:
        id = "SDbKS5b4mBzBMinKiIB6Fh"
        fingerprint = "9159e6c469cea8f7e0a4f51380628cccb44620b782c4d07ecb80068c0d32b58e"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "PureHVNC (PureCoder) -- hidden VNC RAT with ProtoBuf C2, PE injection, credential theft, TLS cert pinning"
        category = "MALWARE"
        malware = "PUREHVNC"
        mitre_att = "T1219"

        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "PureHVNC PureCoder hidden VNC RAT detected."
        yarahub_uuid = "990a9042-ede7-4cdd-ba52-35d132d301a5"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e2759b5ef495bfcfad9074678497f649"

    strings:
        // .NET namespace (plaintext in metadata)
        $ns_purehvnc = "PureHVNC_Lib" ascii

        // Obfuscation attribute marker
        $obf_marker = "EZNRMERM" ascii

        // Assembly GUID
        $guid = "92342e74-3496-442e-8919-4ff580898524" ascii

        // Partially obfuscated namespace
        $ns_obf = "Lhjknyy" ascii wide

        // Canary/junk strings embedded by obfuscator (unique to this build)
        $canary1 = "MKIQFWNK1Zm4dU51L6W" ascii wide
        $canary2 = "IH9HVK9UpOrjBfljU" ascii wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 200KB and filesize < 2MB
        and (
            // Tier 1: namespace is definitive
            $ns_purehvnc
            or (
                // Tier 2: obfuscation marker + obfuscated namespace
                $obf_marker and $ns_obf
            )
            or (
                // Tier 3: GUID + at least one canary
                $guid and 1 of ($canary1, $canary2)
            )
        )
}

rule BruteRatel_C4_Loader
{
    meta:
        id = "o7gUPtSyc4rx18q1QyJnUT"
        fingerprint = "da569ef9491c348880081c879c1d8b8c8a7e5d96dfdacc7937ce89945a1ee26b"
        version = "1.0"
        date = "2026-03-31"
        modified = "2026-03-31"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Brute Ratel C4 stager/loader -- direct syscalls, multiple injection techniques, PPID spoofing"
        category = "MALWARE"
        malware = "BRUTERATEL"
        mitre_att = "T1055.012"

        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Brute Ratel C4 loader with process injection detected."
        yarahub_uuid = "e4cd2b4f-1f41-4d71-9ecc-b4ee2ab4c422"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "def6f8062367490a92ad6650522da0cf"

    strings:
        // BRc4 identification marker (UTF-16LE, appears twice in stagers)
        $marker = "dnSUXRIL" ascii wide

        // Non-standard PE section holding direct syscall stubs
        $sec_sysc = "_sysc" ascii
        // Retpoline stub section
        $sec_retplne = ".retplne" ascii

        // Injection technique log strings (UTF-16LE)
        $inj_earlybird = "Early Bird APC Queue" wide
        $inj_kcb = "KernelCallbackTable" wide
        $inj_threadhijack = "Thread Hijacking" wide
        $inj_sectionview = "Section View Mapping" wide
        $inj_settimer = "Executing shellcode via SetTimer" wide
        $inj_fls = "Executing shellcode via FLS Callback" wide
        $inj_geoid = "Executing shellcode via EnumSystemGeoID" wide
        $inj_linedda = "Executing shellcode via LineDDA" wide
        $inj_clipboard = "Executing shellcode via Clipboard" wide

        // PPID spoofing log
        $ppid_spoof = "Spoofed parent process" wide

        // APC queue confirmation
        $apc_queued = "APC queued" wide

        // Payload decrypt confirmation
        $payload_decrypt = "Payload decrypted" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 100KB and filesize < 2MB
        and (
            // Tier 1: BRc4 marker + custom sections
            $marker and ($sec_sysc or $sec_retplne)
            or (
                // Tier 2: BRc4 marker + injection techniques
                $marker and 2 of ($inj_earlybird, $inj_kcb, $inj_threadhijack, $inj_sectionview, $inj_settimer, $inj_fls, $inj_geoid, $inj_linedda, $inj_clipboard)
            )
            or (
                // Tier 3: custom sections + multiple injection techniques + PPID spoof + operational strings
                ($sec_sysc and $sec_retplne)
                and $ppid_spoof
                and ($apc_queued or $payload_decrypt)
                and 3 of ($inj_earlybird, $inj_kcb, $inj_threadhijack, $inj_sectionview, $inj_settimer, $inj_fls, $inj_geoid, $inj_linedda, $inj_clipboard)
            )
        )
}
