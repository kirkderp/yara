/*
    PyrusKiller Ransomware YARA Rules
    Author: kirkderp
    Date: 2026-03-10
    Source: https://github.com/kirkderp/yara

    Covers:
      1. PyrusKiller PyInstaller PE (packed executable)
      2. PyrusKiller pyc bytecode (extracted/decompressed entry point)

    Tested against 8 known builds (7 unique pyc bytecodes):
      - PyrusKiller.exe    d2b9373235cc063fd66c625e076b7383cde651451b13215c9abbbe8e6ba08ae5
      - PyrusKillerv2.exe  5e5fd5188d2114ce4ac1231d5555cb9e1cda201f93c7b94622d9e445456b0932
      - PyrusKillerv2.exe  21cd27d442611507296b284bb474218212136c3e7c4c5f3daef4fc68887fa481
      - PyrusTakeover.exe  2e69e88652b003e34768a04633e31b5588eb0a250cf75b07bcd629e550fc711d
      - PyrusTakeover.exe  b240d207d6ac526a97ce809433e0300b2bac78b527301e38605d3e215bfb140c
      - PyrusTakeover.exe  b156c0cfc9d67aa6907d4f5dbed19c3c6973ed038bfd68c358f60043571ecb59
      - PyrusTakeover.exe  1789db040b699d2fb948cdd05d363a63c21fe6a49a959ca86f72b4b3809569ca
      - indir.exe          ef6ce8474dabd35ed894906952f33468f8d75c13ff0ef21f45051b17548afade
*/

rule PyrusKiller_PE
{
    meta:
        id = "owlyO1OFyQfF3bstJOcyE5"
        fingerprint = "122085f6d3f1e135f6f3a8ea6a6a502a939e7a3035196b2acf495f8108af2e85"
        version = "1.1"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "PyrusKiller ransomware - PyInstaller packed PE with encrypted payload"
        category = "MALWARE"
        malware = "PYRUSKILLER"
        mitre_att = "T1486"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "PyrusKiller ransomware PyInstaller packed PE detected."

    strings:
        // PyInstaller archive entry for the ransomware entry point
        // TOC entry: typecode 's' (SCRIPT) followed by null-terminated name
        $toc_entry = "sPyrusKiller" ascii

        // PyInstaller bootloader markers
        $pyiboot = "pyiboot01_bootstrap" ascii
        $meipass = "_MEIPASS" ascii

        // Python 3.10 runtime DLL name in the archive TOC
        $py310 = "python310.dll" ascii

    condition:
        uint16(0) == 0x5A4D
        and filesize > 10MB and filesize < 50MB
        and $toc_entry
        and ($pyiboot or $meipass)
        and $py310
}

rule PyrusKiller_PYC
{
    meta:
        id = "agBkPsHZGTnyvO6ZJBIwtL"
        fingerprint = "556774bff7f5d44565073a658baaa5b935f203aa50755bd4d69b58788abbb547"
        version = "1.1"
        date = "2026-03-10"
        modified = "2026-03-10"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "HTTPS://GITHUB.COM/KIRKDERP/YARA"
        author = "kirkderp"
        description = "PyrusKiller ransomware - Python bytecode (extracted pyc or in-memory)"
        category = "MALWARE"
        malware = "PYRUSKILLER"
        mitre_att = "T1486"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "PyrusKiller ransomware Python bytecode detected."

    strings:
        // Registry key for encryption state
        $reg_path = "Software\\PyrusSecurity" ascii

        // Registry value names (unique combination)
        $reg_slaykey = "SlayKey" ascii
        $reg_slaycomplete = "SlayCompleted" ascii
        $reg_notecounter = "NoteCounter" ascii

        // Encryption function name
        $func_slay = "pyrus_slay_files" ascii

        // File extension appended to encrypted files
        $ext_pyrus = ".pyrus" ascii

        // Ransom note content
        $ransom_text = "SLAYED BY PYRUS" ascii

        // Wallpaper filename
        $wallpaper = "pyrus_bg.bmp" ascii

        // Persistence path masquerading as Realtek driver
        $persist_dir = "HD Realtek Sound Driver" ascii
        $persist_runkey = "RealtekAudioUpdate" ascii

        // Password used for account manipulation
        $pass_pyrus = "Your Pass is pyrus" ascii

        // Source filename in code object
        $source_name = "PyrusKiller.py" ascii

    condition:
        // Python 3.10 pyc magic (little-endian): 0x6F0D0D0A
        (uint32(0) == 0x0A0D0D6F or uint32(0) == 0x0A0D0D55)
        and $reg_path
        and $func_slay
        and 3 of ($reg_slaykey, $reg_slaycomplete, $reg_notecounter, $ext_pyrus, $ransom_text, $wallpaper, $pass_pyrus, $source_name)
        or (
            // Also match if found outside a pyc container (memory, scripts)
            filesize < 100KB
            and $reg_path
            and $func_slay
            and ($persist_dir or $persist_runkey)
            and ($ext_pyrus or $wallpaper or $source_name)
        )
}
