/*
    CrystalX Go RAT -- unpacked Go payload rule
    Author: derp.ca
    Date: 2026-05-18
    Source: https://github.com/kirkderp/yara

    Scoped to the recovered Go payload produced by the loader's RCDATA 970
    transform chain.

    Hashes:
        Loader: 34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094
        Payload: a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a
*/

rule CrystalX_Go_RAT
{
    meta:
        id = "a7b3d5e1c8f4b2e6a9d0c3f7a1b4e8d2c5f9a0b3e7d1c4f8a2b5e9d0c6f3a7"
        version = "1.1"
        date = "2026-05-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        yarahub_uuid = "9b56434e-3bd2-4dfa-80bf-4d7f59c552f9"
        description = "CrystalX Go RAT unpacked payload rule using Go, WebSocket path, command, and persistence markers"
        category = "MALWARE"
        malware = "CRYSTALX"
        malware_type = "RAT"
        mitre_att = "T1055.012"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Unpacked CrystalX Go RAT payload with websocket C2 path, remote desktop/file-manager command fragments, and persistence markers."
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "1fc32ba003f385deca86e5ccf8d6ae43"

    strings:
        // Payload/runtime layer
        $go_build = "Go buildinf:" ascii
        $proto_ws_path = "/api/ws" ascii

        // Remote desktop / interaction command fragments
        $cmd_rd_start = "rd_start" ascii
        $cmd_rd_block = "rd_block" ascii
        $cmd_rd_input = "rd_input" ascii
        $cmd_rd_list = "rd_list_" ascii
        $cmd_webcam_start = "webcam_s" ascii
        $cmd_webcam_list = "webcam_l" ascii

        // File manager / collection command fragments
        $cmd_fm_drive = "fm:drive" ascii
        $cmd_fm_ls = "fm:ls:" ascii
        $cmd_fm_del = "fm:del:" ascii
        $cmd_clipboard_set = "clipboard:set:" ascii
        $cmd_steal_manual = "steal:manual" ascii
        $cmd_software_uninstall = "software:uninstall:" ascii

        // Build and environment markers
        $support_task_prefix = "NvContainerTask_" ascii
        $support_build_id = "YBFZUW1U32T" ascii
        $support_string_key = "Hk4fOCLbqKFbbAxwyAcFKUKXK4iqVaMD" ascii
        $support_wc_elv = "WC_ELV" ascii
        $support_geo = "ip-api.com" ascii

    condition:
        uint16(0) == 0x5a4d and
        filesize > 4MB and filesize < 20MB and
        $go_build and
        $proto_ws_path and
        5 of ($cmd_*) and
        1 of ($support_*)
}
