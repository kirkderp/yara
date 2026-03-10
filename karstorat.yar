/*
    KarstoRAT YARA Rules
    Author: derp.ca (ectkirk)
    Date: 2026-03-10
    Reference: (TBD - blog post pending)

    Covers:
      1. KarstoRAT PE - all builds (generic detection)
      2. KarstoRAT Build 4 - anti-analysis + PLAY_SOUND variant
      3. KarstoRAT C2 protocol (network/memory)
      4. KarstoRAT token stealer strings (Builds 2+)

    Tested against all 4 known builds:
      Build 1: aca3f2902307c5ebdb43811b74000783d61b6ad29d7796bb8107d8b1b38d76a3
      Build 2: ee5b0c1f0015b9f59e34ef8017ead6e83259b32c4b0e07dc1f894b0d407094a3
      Build 3: 07131e3fcb9e65c1e4d2e756efdb9f263fd90080d3ff83fbcca1f31a4890ebdb
      Build 4: 839e882551258bf34e5c5105147f7198af2daf7e579d7d4a8c5f1f105966fd7e
*/

rule KarstoRAT_PE
{
    meta:
        id = "aZQQAm3QfB2IR1UHD3PBUZ"
        fingerprint = "cce9c562cc7dfca7b87fb3588dc0748ed210f50074e7f37551485aea39344065"
        version = "1.0"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "derp.ca"
        description = "KarstoRAT native C++ RAT - all builds (author hibby, MSVC x64)"
        category = "MALWARE"
        malware = "KARSTORAT"
        malware_type = "RAT"
        mitre_att = "T1219"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "KarstoRAT remote access trojan detected."

    strings:
        // PDB path - author "hibby", nested Project1 directories
        $pdb = "\\Users\\hibby\\Desktop\\Project1\\" ascii

        // User-Agent used for all WinINet C2 comms
        $ua = "SecurityNotifier" ascii wide

        // C2 heartbeat endpoint (all builds)
        $c2_heartbeat = "/notify?event=heartbeat&user=" ascii
        // C2 log endpoint (all builds)
        $c2_log = "/notify?event=log&user=" ascii

        // C2 upload endpoints
        $ep_screen = "/upload-screen" ascii
        $ep_keylog = "/upload-keylog" ascii
        $ep_sysinfo = "/upload-sysinfo" ascii
        $ep_shell = "/upload-shell-output" ascii
        $ep_webcam = "/upload-webcam" ascii
        $ep_download = "/client-download?user=" ascii

        // Command dispatch strings (unique combination)
        $cmd_screenshot = "SCREENSHOT" ascii wide
        $cmd_keylog_on = "KEYLOG_ON" ascii wide
        $cmd_keylog_off = "KEYLOG_OFF" ascii wide
        $cmd_shell_start = "SHELL_START" ascii wide
        $cmd_shell_input = "SHELL_INPUT:" ascii wide
        $cmd_sysinfo = "SYSINFO" ascii wide
        $cmd_webcam = "WEBCAM" ascii wide
        $cmd_rotate_on = "ROTATE_ON" ascii wide
        $cmd_mouse_swap = "MOUSE_SWAP" ascii wide
        $cmd_wallpaper = "WALLPAPER:" ascii wide
        $cmd_startup_on = "STARTUP_ON" ascii wide
        $cmd_folder_on = "FOLDER_ON" ascii wide
        $cmd_task_on = "TASK_ON" ascii wide

        // Persistence artifacts
        $persist_svc = "SecurityService" ascii wide
        $persist_task = "schtasks /create /f /sc onlogon /tn \"SystemCheck\" /tr \"" ascii

        // Action response format (unique logging pattern)
        $action_fmt = "Action: [" ascii

        // Sysinfo JSON field names (non-standard format, no spaces after colon)
        $json_cpu = "\"cpu\":\"" ascii
        $json_ram = "\"ram_total_gb\":" ascii
        $json_disk = "\"disk_total_gb\":" ascii
        $json_procs = "\"processes\":[" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 50KB and filesize < 500KB
        and (
            // High confidence: PDB + User-Agent
            ($pdb and $ua)
            or
            // High confidence: C2 protocol endpoints
            ($ua and $c2_heartbeat and $c2_log and 2 of ($ep_*))
            or
            // Medium confidence: command dispatch cluster
            (8 of ($cmd_*) and $action_fmt and ($persist_svc or $persist_task))
            or
            // Medium confidence: sysinfo + C2 endpoints
            (3 of ($json_*) and ($c2_heartbeat or $c2_log) and $ua)
        )
}

rule KarstoRAT_Build4
{
    meta:
        id = "wkmOHSBtmAzawl95rZjcmX"
        fingerprint = "fb73b7c5bceb90ea14b834a50a62cfe97a29e100fc1c2e03a935e96bb9f855ac"
        version = "1.0"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "derp.ca"
        description = "KarstoRAT Build 4 variant - anti-analysis, PLAY_SOUND, upload endpoint bug"
        category = "MALWARE"
        malware = "KARSTORAT"
        malware_type = "RAT"
        mitre_att = "T1497.001"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "KarstoRAT Build 4 with anti-analysis and PLAY_SOUND command detected."

    strings:
        $pdb = "\\Users\\hibby\\Desktop\\Project1\\" ascii
        $ua = "SecurityNotifier" ascii wide

        // Anti-analysis process blocklist (Build 4 only)
        $av_x64dbg = "x64dbg.exe" ascii wide
        $av_wireshark = "wireshark.exe" ascii wide
        $av_vmware = "vmware.exe" ascii wide
        $av_vmtoolsd = "vmtoolsd.exe" ascii wide
        $av_vmsrvc = "vmsrvc.exe" ascii wide
        $av_vmusrvc = "vmusrvc.exe" ascii wide
        $av_vboxtray = "vboxtray.exe" ascii wide
        $av_vboxservice = "vboxservice.exe" ascii wide
        $av_df5serv = "df5serv.exe" ascii wide

        // PLAY_SOUND command (Build 4 only)
        $cmd_playsound = "PLAY_SOUND:" ascii wide
        $alarm_file = "alarm.wav" ascii wide

        // Upload endpoint bug - & instead of ? (Build 4 regression)
        $upload_bug = "/client-upload&filename=" ascii

        // Build 4 simplified response format (no "Action: [" prefix on some)
        $resp_simplified1 = "Added to Startup" ascii
        $resp_simplified2 = "Task Created" ascii
        $resp_simplified3 = "Copied to Folder" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 50KB and filesize < 500KB
        and ($pdb or $ua)
        and (
            // Anti-analysis: 5+ of the 9 blocklist names
            (5 of ($av_*))
            or
            // PLAY_SOUND feature
            ($cmd_playsound and $alarm_file)
            or
            // Upload endpoint bug (unique to Build 4)
            $upload_bug
            or
            // Build 4 simplified responses + anti-analysis combo
            (3 of ($resp_simplified*) and 3 of ($av_*))
        )
}

rule KarstoRAT_Token_Stealer
{
    meta:
        id = "eNE3ujpchWIRzIwa8ch7D5"
        fingerprint = "b792b7e5820dfc96972a08b70820e4adca5fa6265ef310072d0476aba4be1fa9"
        version = "1.0"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "derp.ca"
        description = "KarstoRAT token stealer component - Discord + browser credential theft (Builds 2+)"
        category = "MALWARE"
        malware = "KARSTORAT"
        malware_type = "INFOSTEALER"
        mitre_att = "T1528"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "KarstoRAT token stealer targeting Discord and browser credentials detected."

    strings:
        $ua = "SecurityNotifier" ascii wide

        // Discord token paths
        $discord = "\\discord\\Local Storage\\leveldb\\" ascii wide
        $discord_canary = "\\discordcanary\\Local Storage\\leveldb\\" ascii wide
        $discord_ptb = "\\discordptb\\Local Storage\\leveldb\\" ascii wide

        // Browser token paths
        $chrome = "\\Google\\Chrome\\User Data\\Default\\Local Storage\\leveldb\\" ascii wide
        $brave = "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Local Storage\\leveldb\\" ascii wide
        $edge = "\\Microsoft\\Edge\\User Data\\Default\\Local Storage\\leveldb\\" ascii wide
        $opera = "\\Opera Software\\Opera Stable\\Local Storage\\leveldb\\" ascii wide

        // Token regex pattern (embedded in binary)
        $token_regex = "[a-zA-Z0-9_-]{23,28}\\.[a-zA-Z0-9_-]{6}\\.[a-zA-Z0-9_-]{25,110}|mfa\\.[a-zA-Z0-9_-]{84}" ascii

        // Token upload endpoint
        $upload_tokens = "/upload-tokens" ascii

        // TOKEN_GRAB command
        $cmd_tokengrab = "TOKEN_GRAB" ascii wide

        // Action responses
        $resp_found = "Action: [TOKEN_GRAB] -> Found " ascii
        $resp_none = "Action: [TOKEN_GRAB] -> No tokens found" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 50KB and filesize < 500KB
        and (
            // Discord + browser paths + regex = token stealer
            (2 of ($discord*) and 2 of ($chrome, $brave, $edge, $opera) and $token_regex)
            or
            // Token stealer with C2 upload
            ($cmd_tokengrab and $upload_tokens and 2 of ($discord*))
            or
            // User-Agent + token regex + upload = KarstoRAT stealer
            ($ua and $token_regex and $upload_tokens)
            or
            // Token grab responses + paths
            (($resp_found or $resp_none) and 2 of ($discord*))
        )
}

rule KarstoRAT_Network
{
    meta:
        id = "dJKjLzlU7wSFBukw8hrcdp"
        fingerprint = "3e8dd54b7d8cfe192bfedd628c7b310fae60955d7f08d52d3693c0cded8cfcb9"
        version = "1.0"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "derp.ca"
        description = "KarstoRAT C2 protocol indicators - PCAP, memory, or proxy logs"
        category = "MALWARE"
        malware = "KARSTORAT"
        malware_type = "RAT"
        mitre_att = "T1071.001"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "KarstoRAT C2 beacon or command traffic detected."

    strings:
        // User-Agent header in HTTP traffic
        $ua_header = "User-Agent: SecurityNotifier" ascii nocase

        // C2 beacon endpoints in traffic
        $beacon = "/notify?event=heartbeat&user=" ascii
        $log = "/notify?event=log&user=" ascii

        // Data exfiltration endpoints
        $exfil_screen = "/upload-screen" ascii
        $exfil_keylog = "/upload-keylog" ascii
        $exfil_sysinfo = "/upload-sysinfo" ascii
        $exfil_shell = "/upload-shell-output" ascii
        $exfil_webcam = "/upload-webcam" ascii
        $exfil_audio = "/upload-audio" ascii
        $exfil_clipboard = "/upload-clipboard" ascii
        $exfil_tokens = "/upload-tokens" ascii

        // Command retrieval
        $cmd_upload = "/client-upload?user=" ascii
        $cmd_upload_bug = "/client-upload&filename=" ascii
        $cmd_shell_input = "/get-shell-input" ascii

        // Known C2 infrastructure
        $c2_ip = "212.227.65.132" ascii wide
        $c2_ngrok = "hallucinative-shabbily-olga.ngrok-free.dev" ascii wide

        // External IP check
        $ipcheck = "http://api.ipify.org" ascii

    condition:
        // Not PE-only - works on PCAP, memory dumps, proxy logs
        (
            // C2 beacon traffic
            ($ua_header and ($beacon or $log))
            or
            // Data exfiltration traffic
            ($ua_header and 2 of ($exfil_*))
            or
            // C2 protocol endpoints in any file
            ($beacon and $log and 3 of ($exfil_*))
            or
            // Known infrastructure IOCs with protocol
            (($c2_ip or $c2_ngrok) and ($beacon or $log or 2 of ($exfil_*)))
            or
            // Upload endpoints (normal + buggy) with exfiltration
            (($cmd_upload or $cmd_upload_bug) and $cmd_shell_input and 2 of ($exfil_*))
            or
            // IP check + beacon + exfiltration
            ($ipcheck and ($beacon or $log) and 2 of ($exfil_*))
        )
}
