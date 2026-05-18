/*
    Eimeria RAT -- Multi-Stage Loader Chain YARA Rule
    Author: derp.ca
    Date: 2026-05-18
    Source: https://github.com/kirkderp/yara

    Five-layer RAR5-to-RunPE loader chain:
      RAR5 archive -> dsclock.exe (signed carrier) side-loads zlibwapi.dll
      -> zlibwapi.dll AES-128-CBC decrypts msbuilder64.dll
      -> decrypted IExpress archive extracts 26 encrypted blobs
      -> Deal.exe (AutoIt) RunPE hollowing -> .NET C2 beacon ws://94.26.90.139:3006

    Detection targets:
      - zlibwapi.dll: AES-128-CBC SBOX + RCON + BCrypt in small PE DLL
      - dsclock.exe: signed carrier with Duality Software Co. Ltd. cert
      - AutoIt RunPE loader with process hollowing API calls

    Hashes:
        RAR5: c872cd101d9c2a773f08558dde7b716161cf977d4aa99c2347c0269423434f8c
        zlibwapi.dll: 53abc3c2f3e919ecd84724439b4d4fb679857316c6af91987e6db1dde9e8a198
        Deal.exe: 5d69a932a077fee044b193c28e84564143f5c7e51079ab48e88fef74ab0b77b7
*/

rule Eimeria_MultiStage_Loader
{
    meta:
        id = "4KwQv5HVdzRxtlSq39Hu2t"
        fingerprint = "a6b4c8d2e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6"
        version = "2.0"
        date = "2026-05-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "Eimeria RAT: multi-layer loader chain detection targeting zlibwapi.dll (AES+BCrypt), dsclock.exe (signed carrier Duality Software), and AutoIt RunPE loader with process hollowing API calls"
        category = "MALWARE"
        malware = "EIMERIA"
        malware_type = "RAT"
        mitre_att = "T1055.012"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Eimeria multi-stage loader family"
        yarahub_uuid = "41ee8f0e-3835-46fd-b5c6-6321117ba729"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f8a9f400ee56eb3bb2d539fa662b60da"

    strings:
        // zlibwapi.dll -- hidden AES loader
        $aes_sbox = {63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76}
        $rcon = {01 02 04 08 10 20 40 80 1b 36}
        $bcrypt_dll = "bcrypt.dll" ascii

        // dsclock.exe -- signed carrier (PDB path + signer)
        $dsclock_pdb = "DSClock.x86.pdb" ascii
        $dsclock_signer = "Duality Software Co. Ltd." ascii

        // AutoIt x64 compiled executable markers
        $autoit_runtime = "AUTOIT CONSULTING LTD" ascii
        $autoit_eula = "It is a violation of the AutoIt EULA" ascii

        // Process hollowing API calls (via AutoIt DllCall)
        $api_createproc = "CreateProcess" ascii
        $api_valloc = "VirtualAllocEx" ascii
        $api_writeproc = "WriteProcessMemory" ascii
        $api_resume = "ResumeThread" ascii
        $api_readproc = "ReadProcessMemory" ascii

    condition:
        uint16(0) == 0x5A4D
        and (
            // zlibwapi.dll: AES SBOX + RCON + BCryptGenRandom in a small DLL
            ($aes_sbox and $rcon and $bcrypt_dll and filesize < 200KB)
            or
            // dsclock.exe: signed carrier PDB path + Duality Software signer
            ($dsclock_pdb and $dsclock_signer)
            or
            // AutoIt RunPE loader: AutoIt x64 runtime + process hollowing API calls
            ($autoit_runtime and $autoit_eula and
             3 of ($api_createproc, $api_valloc, $api_writeproc, $api_resume, $api_readproc))
        )
}
