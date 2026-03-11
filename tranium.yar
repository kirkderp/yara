/*
    Tranium Wiper YARA Rule
    Author: kirkderp
    Date: 2026-03-10
    Source: https://github.com/kirkderp/yara

    Go wiper/ransomware hybrid with MBR overwrite, system file destruction,
    10 persistence mechanisms, AES-CBC encryption, and BSOD trigger.
    Named after YouTuber "Tranium" (virus testing content creator).

    SHA256: 06430cf9e0ec9fb5b783db7c01fd59bd651d8877143fc45d2bcd7e4dedaf94a6
    VT: 9/76 (2026-03-10), Kaspersky: VHO:Trojan-Ransom.Win32.Agent.gen
*/

rule Tranium_Wiper
{
    meta:
        id = "5jzddCpeqgA5_Drcqh0t2w"
        fingerprint = "2817c33002e5a7d4be63b98715f6c6aaa798ca71cdf1a00aef223bd469f9e368"
        version = "1.0"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "Tranium wiper - Go binary with MBR overwrite, system file destruction, AES-CBC encryption, 10 persistence mechanisms, and BSOD trigger"
        category = "MALWARE"
        malware = "TRANIUM"
        mitre_att = "T1561.002"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Tranium wiper detected. MBR overwrite, system file destruction, file encryption, and BSOD trigger."

    strings:
        // Ransom/wiper identity strings
        $hello = "Hello Tranium" ascii
        $ransom_msg = "Where hath your files gone?" ascii

        // Mutex (unique GUID)
        $mutex = "{F9E3B4A1-2D5C-4F8B-9A6E-1C7D3B5A8F2E}" ascii

        // Persistence GUIDs (unique to Tranium)
        $guid_run = "{D4E5F6A1-B2C3-4D5E-6F7A-8B9C0D1E2F3A}" ascii
        $guid_startup = "{E5F6A1B2-C3D4-4E5F-6A7B-8C9D0E1F2A3B}" ascii
        $guid_svc = "{C3D4E5F6-A1B2-4C9D-0E1F-2A3B4C5D6E7F}" ascii

        // C2/file hosting domains
        $domain1 = "autism.lat" ascii
        $domain2 = "thegumonmyshoe.me" ascii

        // Unique file paths on hosting infra
        $url_bmp = "v73d2.bmp" ascii
        $url_wav = "UPiQj.wav" ascii

        // Wiper behavior indicators
        $bootexec = "autocheck autochk" ascii
        $physdrive = "PhysicalDrive" ascii
        $shadow = "wmic shadowcopy delete" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 4MB and filesize < 10MB
        and (
            // High confidence: identity strings
            ($hello and $ransom_msg)
            or
            // High confidence: unique mutex + any persistence GUID
            ($mutex and 1 of ($guid_run, $guid_startup, $guid_svc))
            or
            // Medium confidence: domain + ransom + wiper behavior
            (1 of ($domain1, $domain2) and $ransom_msg and ($physdrive or $shadow))
            or
            // Medium confidence: persistence GUID combo + wiper behavior
            (2 of ($guid_run, $guid_startup, $guid_svc) and ($physdrive or $bootexec or $shadow))
            or
            // Medium confidence: unique URL paths + wiper behavior
            ($url_bmp and $url_wav and ($physdrive or $shadow))
        )
}
