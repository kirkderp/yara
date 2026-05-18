/*
    CrystalX Go RAT -- Loader + Go Payload YARA Rule
    Author: derp.ca
    Date: 2026-05-18
    Source: https://github.com/kirkderp/yara

    CrystalX Go RAT delivered as NursultanCracked.exe. Three-stage loader
    unpacks Go payload from RCDATA 970 (XOR -> ChaCha20 -> DEFLATE).
    Go payload uses AES-GCM string obfuscation, TLS websocket C2 at
    wss://crystalxrat.net/api/ws, build ID YBFZUW1U32T.

    Hashes:
        Loader: 34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094
        Payload: a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a
*/

rule CrystalX_Go_RAT
{
    meta:
        id = "a7b3d5e1c8f4b2e6a9d0c3f7a1b4e8d2c5f9a0b3e7d1c4f8a2b5e9d0c6f3a7"
        version = "1.0"
        date = "2026-05-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        yarahub_uuid = "9b56434e-3bd2-4dfa-80bf-4d7f59c552f9"
        description = "CrystalX Go RAT: unpacked Go payload with build ID YBFZUW1U32T, AES-GCM key, and Go WebSocket C2 infrastructure"
        category = "MALWARE"
        malware = "CRYSTALX"
        malware_type = "RAT"
        mitre_att = "T1055.012"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "CrystalX Go RAT with websocket C2, AES-GCM obfuscation, and browser credential theft"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1fc32ba003f385deca86e5ccf8d6ae43"

    strings:
        // CrystalX build ID
        $build_id = "YBFZUW1U32T" ascii

        // AES-GCM string decryption key
        $aes_key = "Hk4fOCLbqKFbbAxwyAcFKUKXK4iqVaMD" ascii

        // CrystalX-specific persistence/config strings
        $persist_task = "NvContainerTask_YBFZUW1U32" ascii
        $mutex_name = "WinSecMutex_YBFZUW1U32" ascii
        $wc_elv = "WC_ELV" ascii

        // Go runtime markers (identifies Go-compiled PE)
        $go_runtime = "Go buildinf:" ascii

    condition:
        uint16(0) == 0x5A4D
        and (
            // Unpacked Go payload: build ID + AES key + Go runtime
            ($build_id and $aes_key and $go_runtime)
            or
            // Unpacked Go payload: build ID + persistence + Go runtime
            ($build_id and $persist_task and $go_runtime)
            or
            // Unpacked Go payload: build ID + mutex + WC_ELV
            ($build_id and $mutex_name and $wc_elv)
        )
}
