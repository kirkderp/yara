/*
    GhostWeaver / Pantera RAT YARA Rules
    Author: derp.ca (ectkirk)
    Date: 2026-03-08
    Reference: https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat

    Covers:
      1. GhostWeaver obfuscated PS1 RAT (builder output, on-disk)
      2. GhostWeaver decoded PS1 RAT (post-deobfuscation / memory)
      3. GhostWeaver persistence installer (C2-delivered IEX payload)
      4. GhostWeaver pinned TLS certificate
      5. MintsLoader victim profiler (TAG-124 scoring stage)
      6. MintsLoader JS dropper (TAG-124 stage-1)

    Tested against 5 known GhostWeaver PS1 builds, 1 PE32 packer,
    1 persistence installer, and 2 MintsLoader samples.
*/

rule GhostWeaver_PS1_Obfuscated
{
    meta:
        id = "4yK2n9g8FzSWbGDNR8CDEB"
        fingerprint = "30999b8e0e0921d43835dfac174c058c046ff04835f999b137a895cfc4fd3ba5"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "GhostWeaver/Pantera RAT - obfuscated PowerShell builder output"
        category = "MALWARE"
        malware = "GHOSTWEAVER"
        mitre_att = "T1059.001"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "GhostWeaver/Pantera RAT obfuscated PowerShell builder output detected."

    strings:
        $builder_stamp = /\$global:keystr=streams\\[0-9]{3}\\stub\\[0-9]{8,15}/ ascii wide

        $arith_decoder1 = "[system.String]::new(@((" ascii wide nocase
        $arith_decoder2 = "[char[]]@((" ascii wide nocase

        $arith_sep = "),(" ascii wide

        $exec_ctx = "$executioncontext" ascii wide nocase

        $join_op = "-join ''" ascii wide

    condition:
        filesize > 200KB and filesize < 1MB
        and (
            $builder_stamp
            or (
                ($arith_decoder1 or $arith_decoder2)
                and #arith_sep > 500
                and $exec_ctx
                and $join_op
            )
        )
}

rule GhostWeaver_PS1_Decoded
{
    meta:
        id = "4gcK8OxIKebmDMhHw8lPiz"
        fingerprint = "02f00e7859c9852f022babbe93938651acf2eab3dc4f1c026b6b85d869cd6490"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "GhostWeaver/Pantera RAT - decoded PowerShell (memory or post-deobfuscation)"
        category = "MALWARE"
        malware = "GHOSTWEAVER"
        mitre_att = "T1059.001"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "GhostWeaver/Pantera RAT decoded PowerShell payload detected."

    strings:
        $proto_ssl = "SslStream" ascii wide nocase
        $proto_gzip = "GzipStream" ascii wide nocase
        $proto_json_in = "ConvertFrom-Json" ascii wide nocase
        $proto_json_out = "ConvertTo-Json" ascii wide nocase
        $proto_sslproto = "SslProtocols" ascii wide nocase

        $beacon = "'ClientInfo'" ascii wide
        $cmd_iex = "'iex'" ascii wide
        $cmd_plugin = "'plugin'" ascii wide
        $cmd_selfdelete = "'selfdelete'" ascii wide
        $cmd_saveplugin = "'savePlugin'" ascii wide
        $cmd_sendplugin = "'sendPlugin'" ascii wide

        $mutex = "euzizvuze" ascii wide

        $port = "25658" ascii wide

        $dga_random = "System.Random" ascii wide nocase
        $dga_doy = "DayOfYear" ascii wide nocase
        $dga_tld_top = ".top" ascii wide
        $dga_tld_fun = ".fun" ascii wide
        $dga_tld_xyz = ".xyz" ascii wide
        $dga_tld_cn = ".cn" ascii wide

    condition:
        (2 of ($proto_*))
        and (
            ($beacon and 3 of ($cmd_*))
            or
            ($mutex and $port and $dga_random and $dga_doy and 3 of ($dga_tld_*))
            or
            (4 of ($cmd_*) and $mutex)
        )
}

rule GhostWeaver_Persistence_Installer
{
    meta:
        id = "5JZRC0pj4MOxL8jRH8TIdt"
        fingerprint = "41f3bcd5aae841a7d831853422f12593f6f9a8e7f492f4f24c54496f4ae1939e"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "GhostWeaver/Pantera persistence installer delivered via C2 iex command"
        category = "MALWARE"
        malware = "GHOSTWEAVER"
        mitre_att = "T1548.002"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "GhostWeaver/Pantera persistence installer with UAC bypass detected."

    strings:
        $uac_guid = "A6BFEA43-501F-456F-A845-983D3AD7B8F0" ascii wide nocase
        $uac_coget = "CoGetObject" ascii wide
        $uac_elevation = "Elevation:Administrator!new:" ascii wide

        $peb_func = "Masquerade-PEB" ascii wide
        $headless = "--headless powershell" ascii wide
        $headless_cmd = "--headless cmd" ascii wide

        $schtask_interval = "PT3M" ascii wide
        $schtask_desc = "Maintenance task" ascii wide
        $dpapi = "DataProtectionScope" ascii wide nocase
        $azure_prefix = /Azure[A-Za-z]+\.(ps1|log|jpg)/ ascii wide

    condition:
        ($uac_guid and ($uac_coget or $uac_elevation))
        or
        ($peb_func and ($headless or $headless_cmd))
        or
        ($schtask_interval and $schtask_desc and ($headless or $headless_cmd))
        or
        ($dpapi and ($headless or $headless_cmd) and $azure_prefix)
}

rule GhostWeaver_TLS_Certificate
{
    meta:
        id = "2PS1wclvHTVqqWL0fNQQnE"
        fingerprint = "6c09c97d19548a9db9519f2cb4ad85ac3f2a363899775f896afbb9ebd36f8ab4"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "GhostWeaver/Pantera pinned self-signed TLS certificate (CN=GeoTrust LTD.)"
        category = "MALWARE"
        malware = "GHOSTWEAVER"
        mitre_att = "T1553.004"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "GhostWeaver/Pantera pinned TLS certificate detected."

    strings:
        $cert_der = {
            30 82 04 ee 30 82 02 d6  // SEQUENCE headers
            a0 03 02 01 02 02 10 00  // version + serial prefix
            9e d7 a1 52 31 31 20 57  // serial number (unique)
            1a 4e 51 63 87 70 69 30  // serial + algo prefix
        }

        $cert_b64 = "MIIE7jCCAtagAwIBAgIQAJ7XoVIxMSBXGk5RY4dwa" ascii wide

        $cert_cn_str = "GeoTrust LTD." ascii wide

        $cert_sha1 = { 00 6f 5b b9 27 20 ac a3 3a ab 33 50 5e 17 c4 2c c2 f9 f2 36 }

    condition:
        any of them
}

rule MintsLoader_Victim_Profiler
{
    meta:
        id = "1NXLHyr8lbJ1fnH1QXX29d"
        fingerprint = "76cb07d1866e0bc442d0ae6b214fcfd5d123d986d020c58bf7d9b1129715eedf"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "MintsLoader/TAG-124 victim profiler - sandbox detection and scoring"
        category = "MALWARE"
        malware = "MINTSLOADER"
        mitre_att = "T1497.001"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "MintsLoader/TAG-124 sandbox scoring and victim profiling detected."

    strings:
        $check_vm = "IsVirtualMachine" ascii wide nocase
        $check_gpu = "AdapterDACType" ascii wide nocase
        $check_cache = "CacheMemory" ascii wide nocase
        $check_video = "Win32_VideoController" ascii wide nocase

        $amsi = "AmsiOpenSession" ascii wide

        $callback_htr = /[a-z0-9]{5,15}htr[a-z0-9]{3,8}\.php/ ascii wide
        $callback_param_key = "&key=" ascii wide
        $callback_param_s = "&s=" ascii wide

        $dga4_charset = "'abcdefghijklmn'" ascii wide

    condition:
        (($check_vm or $amsi) and ($check_gpu or $check_cache) and $check_video)
        or
        ($callback_htr and $callback_param_key and $callback_param_s)
        or
        ($dga4_charset and ($check_vm or $check_gpu or $check_cache))
}

rule MintsLoader_JS_Dropper
{
    meta:
        id = "6SZfp0qlIsOShAB3dnLBkq"
        fingerprint = "4e38a8d263fef79611f3e1221573773c4a4537874e575c6e962c76ea48bf61dd"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "MintsLoader/TAG-124 JavaScript dropper - XOR-obfuscated, delivers PowerShell"
        category = "MALWARE"
        malware = "MINTSLOADER"
        mitre_att = "T1059.007"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "MintsLoader/TAG-124 XOR-obfuscated JavaScript dropper detected."

    strings:
        $cc_on = "//@cc_on" ascii

        $obf_func = /a0_0x[0-9a-fA-F]{3,8}/ ascii
        $str_mlhttp = "MLHTT" ascii
        $str_activex = "eXObj" ascii
        $str_wsh = "'WSH'" ascii
        $str_post = "'POST'" ascii
        $str_eval = "'eval'" ascii

        $delivery_url = /\/1\.php\?s=[0-9a-f\-]{8,40}/ ascii
        $delivery_url2 = /\/1\.php\?s=flibabc[0-9]{1,3}/ ascii

        $activex_shell = "WScript.Shell" ascii wide

    condition:
        filesize < 50KB
        and $cc_on
        and (
            (#obf_func > 10 and 3 of ($str_*))
            or
            (($delivery_url or $delivery_url2) and $activex_shell)
        )
}

rule GhostWeaver_Network_Indicators
{
    meta:
        id = "5nlhxIWY2MajrhjApbjA04"
        fingerprint = "2ae818b4786a04722abd38415114d19f5d71b2e2eccbc146c832f1429dd238bd"
        version = "1.0"
        date = "2026-03-08"
        modified = "2026-03-08"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://WWW.DERP.CA/BLOG/GHOSTWEAVER-TAG124-POWERSHELL-RAT"
        author = "derp.ca"
        description = "GhostWeaver/Pantera network-level indicators (C2 traffic, DGA domains)"
        category = "MALWARE"
        malware = "GHOSTWEAVER"
        mitre_att = "T1568.002"
        reference = "https://www.derp.ca/blog/ghostweaver-tag124-powershell-rat"
        triage_score = 10
        triage_description = "GhostWeaver/Pantera C2 beacon or command traffic detected."

    strings:
        $json_clientinfo = /\"Packet\":\s?\"ClientInfo\"/ ascii nocase
        $json_ping = /\"Packet\":\s?\"Ping\"/ ascii nocase
        $json_pong = /\"Packet\":\s?\"pong\"/ ascii nocase
        $json_hwid = /\"HWID\":\s?\"/ ascii
        $json_version = /\"Version\":\s?\"/ ascii
        $json_group = /\"Group\":\s?\"/ ascii
        $json_plugin = /\"Packet\":\s?\"plugin\"/ ascii nocase
        $json_sendplugin = /\"Packet\":\s?\"sendPlugin\"/ ascii nocase
        $json_iex = /\"Packet\":\s?\"iex\"/ ascii nocase

    condition:
        ($json_clientinfo and $json_hwid and $json_version and $json_group)
        or
        ($json_plugin and $json_sendplugin)
        or
        (($json_pong or $json_ping) and ($json_iex or $json_plugin))
}
