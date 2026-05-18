# Eimeria: five-layer RAR5-to-RunPE loader chain

**YARA Rule**: [Eimeria_MultiStage_Loader.yar](Eimeria_MultiStage_Loader.yar)

| | |
|---|---|
| **Family** | eimeria (Triage-assigned) |
| **Archive SHA256** | `c872cd101d9c2a773f08558dde7b716161cf977d4aa99c2347c0269423434f8c` |
| **First seen** | 2026-05-08 |
| **C2** | `94.26.90[.]139:3006` (Dedik Services Ltd, Frankfurt, DE) |
| **Triage** | 10/10 -- [260508-n6jeqagv2w](https://tria.ge/260508-n6jeqagv2w) |
| **VT** | Archive 1/74, zlibwapi.dll 4/68, dsclock.exe 0/70 |

The hash surfaced through C2 feed toward `94.26.90[.]139:3006`, a bare IP on Dedik Services Limited in Frankfurt. The RAR5 archive contains four files under `jjez/`. Triage flagged two score-10 and extracted a WebSocket C2 from memory dump. Five-layer chain: signed carrier, zlib DLL with hidden AES, IExpress archive, AutoIt process hollowing, .NET C2 beacon.

## Detection

YARA rule: [Eimeria_MultiStage_Loader.yar](Eimeria_MultiStage_Loader.yar)

The rule is scoped to the observed malicious loader components and has two branches:

1. `zlibwapi.dll`: PE32 DLL, zlib exports, `BCryptGenRandom`, AES SBOX/RCON constants, and loader process creation import.
2. `Deal.exe`: PE32+ AutoIt runtime with RunPE process hollowing imports.

Validation matched `zlibwapi.dll` and the recovered `Deal.exe` runtime artifact. The clean signed carrier `dsclock.exe`, bundled `libcurl.dll`, encrypted `msbuilder64.dll`, submitted RAR container, and adjacent local breach corpus samples stayed clean.

## Layer 0: the RAR5 bundle

| File | Size | Type | Triage | VT |
|---|---|---|---|---|
| dsclock.exe | 1,679,312 | PE32 GUI x86, signed | 10 | 0/70 |
| libcurl.dll | 362,496 | PE32 DLL x86 | 3 | -- |
| msbuilder64.dll | 4,652,720 | Encrypted blob | 1 | 0/61 |
| zlibwapi.dll | 93,696 | PE32 DLL x86 | 10 | 4/68 |

## Layer 1: signed carrier and zlib DLL loader

`dsclock.exe` has been on VT since 2022 (0/70) and shows no malicious behaviour on its own. Signed by Duality Software Co. Ltd., PDB `DSClock.x86.pdb`. The attack vector is DLL side-loading -- Windows loads `zlibwapi.dll` from the same `jjez/` directory before checking system paths.

`zlibwapi.dll` exports the usual zlib and minizip entry points (deflate, inflate, compress, uncompress) but hidden in its .text section is an AES-128-CBC decryption engine with its own SBOX table (at 0xdf80, confirmed starting `63 7c 77 7b`) and RCON values (at 0xe080). Capa confirmed PE header parsing, section enumeration, CreateProcess, BCryptGenRandom, and file I/O capabilities that do not belong in a zlib wrapper.

The AES key is runtime-derived via BCryptGenRandom. The IV is the first 16 bytes of the encrypted payload. A known-plaintext pair is available for verification: msbuilder64.dll (ciphertext) and GxNWZFTx.exe (decrypted plaintext).

## Layer 2: IExpress self-extracting archive

The decrypted payload is a PE32+ (x86-64) executable identified by capa as an IExpress self-extracting archive. We extracted the embedded CAB file from the IExpress stub at file offset 0x2a830. The CAB is 4,478,592 bytes and contains 26 files with .potm extensions (PowerPoint macro template) and short data-blob names.

The .potm extensions are decoys. None of the files are actual PowerPoint templates. Every single one is an encrypted binary blob with dictionary-word names (Bus, Centre, Code, Conference, Development, Fuel, Plant, Process, Reference, Relationship, Speed, Supply, Technology, etc.).

At runtime, two additional files appear on disk: `Deal.exe` (1,107,552 bytes, AutoIt-compiled RunPE loader) and `bMgXiqSim` (3,967,774 bytes, encrypted concatenated IExpress content bundle).

## Layer 3: Autoit, RC4, LZNT1, and process hollowing

`Deal.exe` is compiled with AutoIt3 and embeds both the AutoIt runtime and a 24,773-line compiled pcode script. The script implements a full RunPE (process hollowing) loader:

1. **Restore ntdll from disk** (`RESTORENTDLLHOOKS`) -- removes userland EDR hooks by reloading ntdll from the filesystem.
2. **RC4 decrypt** (`DECRYPT_RC4_SHELLCODE`) -- decrypts embedded payload hex (2.4 MB) with key `wNDRKtWS12MEvmD4jr3ZyvqQTviBYboE5Ce`.
3. **LZNT1 decompress** (`DECOMPRESS_LZNT1`) -- decompresses via ntdll!RtlDecompressBuffer (format 2, big-endian headers).
4. **Select injection target** -- enumerates processes for suitable hosts (explorer.exe, svchost.exe, taskhostw.exe).
5. **Hollow and inject** (`RUNPE_EXACT`) -- CreateProcess suspended, NtUnmapViewOfSection, VirtualAllocEx, WriteProcessMemory, fix imports, SetThreadContext, ResumeThread.
6. **Architecture detection** -- handles x86/x64 injection and detects .NET assemblies for alternative handling.

The final injected payload is a 5.8 KB Mono/.NET assembly that serves as the C2 beacon.

## Anti-analysis

| Check | Mechanism |
|---|---|
| Ntdll restoration | Reloads ntdll from disk to remove EDR hooks |
| Natural delay | 28-second delay before any malicious behaviour |
| Anti-emulation | Pi calculation: 1M iterations of sum(1/n^2), checks sqrt(sum*6) > 3.1415 |
| Sleep check | Compares real vs emulated sleep duration |
| Stress test | CPU/memory stress test for thin VPS detection |
| Memory purge | Calls EmptyWorkingSet to evade memory scanners |
| Secure zeroing | RtlZeroMemory on sensitive buffers after use |

## Persistence

| Mechanism | Detail |
|---|---|
| Run key | `HKCU\...\Run\ReportFootballHost_EXX` |
| Executable | `AppData\Local\Material\ReportFootballHost\KitchenTaylor.exe` |
| Pcode | `AppData\Local\Material\ReportFootballHost\HorseLiterature.a3x` |
| Task Scheduler | `Material_ReportFootballHost_Startup` (logon trigger) |

## C2

| Detail | Value |
|---|---|
| Endpoint | `94.26.90[.]139:3006` |
| Provider | Dedik Services Ltd (AS207043), Frankfurt am Main, DE |
| VT status | 11/92 malicious |
| Liveness | Confirmed at intake (nc -vz succeeded) |
| Protocol | WebSocket (ws:// schema from config extraction) |

The C2 was live on 2026-05-12 via `nc -vz`. Triage sandbox reached it but received no response bytes -- the server either blocks sandbox IPs or did not recognize the request shape.

## Lineage

"Eimeria" is a Triage-assigned label, not a known public family. The most comparable known family is DarkGate, which also uses AutoIt + RC4 + RunPE with ntdll restoration. However, the architectural differences are significant:

- Five-layer delivery chain (RAR5 -> signed EXE -> zlib DLL -> IExpress -> AutoIt) vs DarkGate's single AutoIt script
- Signed carrier (Duality Software Co. Ltd.) -- 0% detection on 143 prior files. Likely stolen or compromised certificate.
- zlibwapi.dll disguise -- AES hidden inside a legitimate zlib DLL
- WebSocket C2 instead of HTTP/HTTPS
- RAR5 initial container is uncommon for this style of loader

Assessment: custom loader/RAT chain built by someone familiar with DarkGate's methodology, with a distinct delivery chain and C2 shape.



### Hashes

| File | SHA256 |
|---|---|
| RAR5 archive | `c872cd101d9c2a773f08558dde7b716161cf977d4aa99c2347c0269423434f8c` |
| dsclock.exe | `62fdad7df8fd7bc2b211c2de06c002831b36987b48a943758432f25006661578` |
| zlibwapi.dll | `53abc3c2f3e919ecd84724439b4d4fb679857316c6af91987e6db1dde9e8a198` |
| msbuilder64.dll | `e155acf50ab0dad1a80f0a67d396d0ad5691fc9e314e4efd1da1dd3180c9632f` |
| GxNWZFTx.exe (IExpress) | `84fdf804149920cb474a030479fda1d5c9a5939388353054169ec692b8f75d3a` |
| Deal.exe (AutoIt) | `5d69a932a077fee044b193c28e84564143f5c7e51079ab48e88fef74ab0b77b7` |

### Network

| Type | Value | Context |
|---|---|---|
| IP:Port | `94.26.90[.]139:3006` | C2 WebSocket endpoint |
| Provider | Dedik Services Ltd (AS207043) | Frankfurt am Main, Germany |

### Host

| Indicator | Value |
|---|---|
| Persistence path | `%LOCALAPPDATA%\Material\ReportFootballHost\KitchenTaylor.exe` |
| Pcode path | `%LOCALAPPDATA%\Material\ReportFootballHost\HorseLiterature.a3x` |
| Run key | `HKCU\...\Run\ReportFootballHost_EXX` |
| Scheduled task | `Material_ReportFootballHost_Startup` |
| RC4 key | `wNDRKtWS12MEvmD4jr3ZyvqQTviBYboE5Ce` |
| Compression | LZNT1 (ntdll!RtlDecompressBuffer, format 2) |
| AES mode | AES-128-CBC with prepended IV |
