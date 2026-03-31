rule ECHidna_RAT
{
    meta:
        id = "CSu4wu3qHviulG2rMh6upJ"
        fingerprint = "cfdc137399b7363d73f59d210a805e2eaa3b6ba90f2c27fa8c67375524f9fce1"
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
        yarahub_uuid = "c8c1e31a-ecce-4ec8-b378-ee8e95245959"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "5321d27958a11f9744cf23be0204f386"

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
