/*
    Eimeria RAT -- Multi-Stage Loader Chain YARA Rule
    Author: derp.ca
    Date: 2026-05-16
    Source: https://github.com/kirkderp/yara

    Five-layer RAR5-to-RunPE loader chain: signed carrier (dsclock.exe) ->
    zlibwapi.dll hidden AES loader -> msbuilder64.dll AES-CBC decryption ->
    IExpress self-extracting archive -> AutoIt RunPE hollowing (RC4+LZNT1)
    -> .NET C2 beacon at ws://94.26.90.139:3006

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
        version = "1.0"
        date = "2026-05-16"
        modified = "2026-05-16"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "derp.ca"
        description = "Eimeria RAT -- five-layer loader chain: RAR5, zlib DLL with hidden AES, IExpress archive, AutoIt RunPE hollowing (RC4+LZNT1), .NET C2 beacon at ws://94.26.90.139:3006"
        category = "MALWARE"
        malware = "EIMERIA"
        malware_type = "RAT"
        mitre_att = "T1055.012"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Eimeria multi-stage loader detected. Five-layer chain with signed carrier, hidden AES in zlib DLL, IExpress archive, AutoIt process hollowing."
        yarahub_uuid = "41ee8f0e-3835-46fd-b5c6-6321117ba729"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "f8a9f400ee56eb3bb2d539fa662b60da"

    strings:
        // zlibwapi.dll -- hidden AES loader
        $zlib_exports_combined = "deflateinflatecompressuncompresszlibVersionunzOpenzipOpen" ascii
        $aes_sbox_start = {63 7c 77 7b f2 6b 6f c5 30 01 67 2b fe d7 ab 76}
        $rcon_start = {01 02 04 08 10 20 40 80 1b 36}
        $bcrypt_genrandom = "BCryptGenRandom" ascii
        $bcrypt_dll = "bcrypt.dll" ascii

        // dsclock.exe -- signed carrier (PDB path marker)
        $dsclock_pdb = "DSClock.x86.pdb" ascii
        $duality_signer = "Duality Software Co. Ltd." ascii

        // IExpress self-extracting archive markers
        $iexpress_sed = "IExpress" ascii
        $iexpress_makecab = "makecab.exe" ascii
        $iexpress_rundll_del = "DelNodeRunDLL32" ascii

        // AutoIt compiled executable markers
        $autoit_runtime = "AutoIt Error" ascii
        $autoit_corrupt = "AutoIt has detected the stack has become corrupt" ascii
        $require_admin = "#requireadmin" ascii

        // Eimeria-specific AutoIt script strings
        $eimeria_company = "Material" ascii
        $eimeria_appdir = "ReportFootballHost" ascii
        $eimeria_exe = "KitchenTaylor.exe" ascii
        $eimeria_task = "Material_ReportFootballHost_Startup" ascii
        $eimeria_run_key = "ReportFootballHost_EXX" ascii

        // Eimeria AutoIt script anti-analysis
        $antiemu_math = "Anti-Emu" ascii
        $restore_ntdll = "RESTORENTDLLHOOKS" ascii

        // Eimeria RC4+LZNT1 decryption
        $runpe_func = "RUNPE_EXACT" ascii
        $lznt1_func = "DECOMPRESS_LZNT1" ascii
        $rc4_func = "DECRYPT_RC4_SHELLCODE" ascii

        // Eimeria process injection APIs
        $unmap_view = "NtUnmapViewOfSection" ascii
        $set_context = "SetThreadContext" ascii
        $write_proc_mem = "WriteProcessMemory" ascii
        $alloc_ex = "VirtualAllocEx" ascii

        // C2 endpoint

        // RunOnce registry (from rbin emulation)

    condition:
        uint16(0) == 0x5A4D
        and (
            // zlibwapi.dll variant -- hidden AES loader
            ($zlib_exports_combined and $aes_sbox_start and $bcrypt_genrandom and $bcrypt_dll)
            or
            // zlibwapi.dll variant -- AES SBOX + RCON + BCrypt (broader)
            ($aes_sbox_start and $rcon_start and $bcrypt_dll and filesize < 200KB)
            or
            // dsclock.exe variant -- signed carrier
            ($dsclock_pdb and $duality_signer)
            or
            // dsclock.exe variant -- PDB + IExpress
            ($dsclock_pdb and 2 of ($iexpress_sed, $iexpress_makecab, $iexpress_rundll_del))
            or
            // IExpress self-extractor variant
            ($iexpress_sed and $iexpress_makecab and filesize > 4MB and filesize < 5MB)
            or
            // Eimeria AutoIt script -- specific config + RC4/LZNT1
            ($eimeria_company and $eimeria_appdir and $eimeria_exe
             and 2 of ($lznt1_func, $rc4_func, $runpe_func, $antiemu_math, $restore_ntdll))
            or
            // Eimeria AutoIt executable -- runtime markers + config
            ($autoit_runtime and $eimeria_run_key)
            or
            // Eimeria AutoIt -- persistence + process injection
            ($eimeria_task and 3 of ($unmap_view, $set_context, $write_proc_mem, $alloc_ex))
            or
            // Deal.exe AutoIt compiled -- broad detection
            ($autoit_corrupt and $require_admin and $restore_ntdll and $runpe_func)
        )
}
