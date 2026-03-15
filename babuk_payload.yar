/*
    Babuk "Payload" Ransomware YARA Rules
    Author: kirkderp
    Date: 2026-03-15
    Source: https://github.com/kirkderp/yara

    Babuk ransomware variant branded "Payload". Curve25519 ECDH + ChaCha20
    file encryption with RC4("FBI") footer wrapping. Compiled MSVC (VS2019),
    x86 PE console binary.

    Encryption: per-file Curve25519 ECDH + ChaCha20, 1MB chunks,
    56-byte footer RC4-encrypted with static 3-byte key "FBI".
    Ransom note (RECOVER_payload.txt) RC4-encrypted in .rdata.
    Mutex: MakeAmericaGreatAgain.

    SHA256: 1ca67af90400ee6cbbd42175293274a0f5dc05315096cb2e214e4bfe12ffb71f
    VT: 57/76 (2026-02-21), ClamAV: Win.Ransomware.Babuk-10032520-1
*/

rule Babuk_Payload_Ransomware
{
    meta:
        id = "Fuf8T_FxfCEqvOh2npnxDo"
        fingerprint = "b95f09b1cc4c19f58e94548b2a03b6bc3321a66251b23c97ea4c934903f2c2b0"
        version = "1.0"
        date = "2026-03-15"
        modified = "2026-03-15"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Babuk Payload ransomware - Curve25519 + ChaCha20 encryption, RC4 FBI footer key, MakeAmericaGreatAgain mutex"
        category = "MALWARE"
        malware = "BABUK"
        malware_type = "RANSOMWARE"
        mitre_att = "T1486"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Babuk Payload ransomware detected. Curve25519 ECDH + ChaCha20 file encryption, shadow copy deletion, service/process termination."

    strings:
        // Mutex
        $mutex = "MakeAmericaGreatAgain" wide

        // Ransom note and extension
        $note = "RECOVER_payload.txt" wide
        $ext = ".payload" wide

        // RC4 footer key adjacent to ChaCha20 constant in .rdata
        // "expand 32-byte k" + "FBI\0" (contiguous in .rdata)
        $chacha_fbi = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 46 42 49 00 }

        // ASCII art banner (unique to Payload branding)
        $banner = "##m#\"  \"mm\"#" wide

        // CLI switches and config strings (wide)
        $arg_bypass = "bypass-etw" wide
        $arg_bg = "--background" wide

        // Log prefixes (wide)
        $log_enc = "[Encryption] " wide
        $log_cpu = "[CPU] Cores: " wide
        $log_mutex = "[Mutex] locker running.." wide
        $log_mode = "[Mode] Lock all drives" wide
        $log_api = "[API] Failed to init nt!" wide

        // Shadow copy deletion command
        $vss = "/c vssadmin.exe delete shadows /all /quiet" wide

        // Targeted services (ASCII, embedded in .rdata)
        $svc_veeam = "VeeamTransportSvc" ascii
        $svc_qb = "Intuit.QuickBooks.FCS" ascii
        $svc_acronis = "AcronisAgent" ascii
        $svc_360 = "zhudongfangyu" ascii

        // Pubkey size validation
        $pubkey_marker = "SIZE OF PUBKEY IS LOWER THAN NEED (32)" wide

    condition:
        uint16(0) == 0x5A4D
        and filesize > 200KB and filesize < 1MB
        and (
            // High confidence: chacha+FBI key combo (unique to this variant)
            $chacha_fbi
            or
            // High confidence: mutex + ransom note
            ($mutex and $note)
            or
            // High confidence: mutex + extension + any log prefix
            ($mutex and $ext and 1 of ($log_enc, $log_cpu, $log_mutex, $log_mode))
            or
            // Medium confidence: banner + note + vss deletion
            ($banner and $note and $vss)
            or
            // Medium confidence: 3+ log prefixes + extension + shadow deletion
            (3 of ($log_enc, $log_cpu, $log_mutex, $log_mode, $log_api) and $ext and $vss)
            or
            // Medium confidence: CLI switches + pubkey check + services
            ($arg_bypass and $pubkey_marker and 2 of ($svc_veeam, $svc_qb, $svc_acronis, $svc_360))
            or
            // Medium confidence: background flag + extension + services + vss
            ($arg_bg and $ext and 2 of ($svc_veeam, $svc_qb, $svc_acronis, $svc_360) and $vss)
        )
}

rule Babuk_Payload_Ransomware_Broad
{
    meta:
        id = "689B5BmcDeNHVlWHg9Un1X"
        fingerprint = "29cadc3230cb2d2b2632ffc4d8d1583bff07c7d7b64c4db124c35df4a315cce7"
        version = "1.0"
        date = "2026-03-15"
        modified = "2026-03-15"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Babuk Payload ransomware - broader detection for variant builds with different operator keys or configs"
        category = "MALWARE"
        malware = "BABUK"
        malware_type = "RANSOMWARE"
        mitre_att = "T1486"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Babuk Payload ransomware variant detected. ChaCha20 file encryption with FBI footer key."

    strings:
        // ChaCha20 constant + FBI footer key (contiguous .rdata layout specific to Payload variant)
        $chacha_fbi = { 65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B 46 42 49 00 }

        // Ransom note filename
        $note = "RECOVER_payload.txt" wide

        // Extension
        $ext = ".payload" wide

        // Log prefixes unique to the Payload builder
        $log_enc = "[Encryption] " wide
        $log_args = "[Args] " wide
        $log_disk = "[Disk] " wide

        // Mutex name
        $mutex = "MakeAmericaGreatAgain" wide

        // Pubkey size validation
        $pubkey_check = "SIZE OF PUBKEY IS LOWER THAN NEED" wide

        // Process kill list (common Babuk set, at least 3 in sequence)
        $proc1 = "sql.exe" wide
        $proc2 = "oracle.exe" wide
        $proc3 = "ocssd.exe" wide
        $proc4 = "dbsnmp.exe" wide
        $proc5 = "sqbcoreservice.exe" wide

        // Service kill (unique combo)
        $svc1 = "BackupExecVSSProvider" ascii
        $svc2 = "VeeamDeploymentService" ascii
        $svc3 = "zhudongfangyu" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 100KB and filesize < 2MB
        and (
            // Core: ChaCha+FBI key pattern
            ($chacha_fbi and ($note or $ext or $mutex))
            or
            // Note + extension + log framework
            ($note and $ext and 2 of ($log_enc, $log_args, $log_disk))
            or
            // Process kill list + extension + pubkey validation
            (3 of ($proc1, $proc2, $proc3, $proc4, $proc5) and $ext and $pubkey_check)
            or
            // Service kill combo + mutex + note
            (2 of ($svc1, $svc2, $svc3) and $mutex and $note)
        )
}
