# Eimeria: zlib side-load and AutoIt RunPE loader chain

**YARA Rule**: [Eimeria_MultiStage_Loader.yar](Eimeria_MultiStage_Loader.yar)

| | |
|---|---|
| **Family / case** | Eimeria, Triage-assigned |
| **Rule scope** | Loader components from a multi-stage chain |
| **Malware type** | RAT loader |
| **Primary sample SHA256** | `c872cd101d9c2a773f08558dde7b716161cf977d4aa99c2347c0269423434f8c` |
| **Known positive layers** | `zlibwapi.dll`, recovered `Deal.exe` AutoIt loader |
| **Triage** | 10/10 -- [260508-n6jeqagv2w](https://tria.ge/260508-n6jeqagv2w) |
| **Network** | `94.26.90[.]139:3006` |

Eimeria is a RAR5-to-RunPE chain where a signed `dsclock.exe` carrier side-loads a malicious `zlibwapi.dll`. The DLL keeps the normal zlib export surface but adds AES evidence and `BCryptGenRandom`/process-launch imports that do not belong in a plain zlib wrapper. The recovered `Deal.exe` layer is an AutoIt RunPE loader with process hollowing imports.

## Detection

YARA rule: [Eimeria_MultiStage_Loader.yar](Eimeria_MultiStage_Loader.yar)

The rule has two branches:

1. `zlibwapi.dll`: PE32 DLL with zlib exports, `BCryptGenRandom`, `CreateProcessA`, AES SBOX/RCON constants, and `bcrypt.dll`.
2. `Deal.exe`: PE32+ AutoIt runtime with RunPE process-hollowing imports and AutoIt runtime markers.

Validation matched the malicious `zlibwapi.dll` and recovered `Deal.exe` runtime artifact. The signed carrier, bundled `libcurl.dll`, encrypted payload blob, and submitted RAR container stayed clean.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| RAR5 archive | `c872cd101d9c2a773f08558dde7b716161cf977d4aa99c2347c0269423434f8c` |
| `dsclock.exe` signed carrier | `62fdad7df8fd7bc2b211c2de06c002831b36987b48a943758432f25006661578` |
| `zlibwapi.dll` loader | `53abc3c2f3e919ecd84724439b4d4fb679857316c6af91987e6db1dde9e8a198` |
| `msbuilder64.dll` encrypted blob | `e155acf50ab0dad1a80f0a67d396d0ad5691fc9e314e4efd1da1dd3180c9632f` |
| Decrypted IExpress layer | `84fdf804149920cb474a030479fda1d5c9a5939388353054169ec692b8f75d3a` |
| Recovered `Deal.exe` AutoIt loader | `5d69a932a077fee044b193c28e84564143f5c7e51079ab48e88fef74ab0b77b7` |

### Network

| Type | Value | Context |
|---|---|---|
| IP:Port | `94.26.90[.]139:3006` | Extracted WebSocket C2 endpoint |

### Host

| Indicator | Value |
|---|---|
| Persistence executable | `%LOCALAPPDATA%\Material\ReportFootballHost\KitchenTaylor.exe` |
| Pcode path | `%LOCALAPPDATA%\Material\ReportFootballHost\HorseLiterature.a3x` |
| Run key | `HKCU\...\Run\ReportFootballHost_EXX` |
| Scheduled task | `Material_ReportFootballHost_Startup` |
| RC4 key | `wNDRKtWS12MEvmD4jr3ZyvqQTviBYboE5Ce` |
| Compression | LZNT1 via `RtlDecompressBuffer` |

## References

- Triage task: https://tria.ge/260508-n6jeqagv2w
- YARA repository: https://github.com/kirkderp/yara
