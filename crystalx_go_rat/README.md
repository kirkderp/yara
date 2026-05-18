# CrystalX Go RAT -- YARA Rule

**YARA Rule**: [CrystalX_Go_RAT.yar](CrystalX_Go_RAT.yar)

| | |
|---|---|
| **Family** | crystalx (Triage-assigned) |
| **Loader SHA256** | `34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094` |
| **Payload SHA256** | `a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a` |
| **First seen** | 2026-05-11 |
| **C2** | `hxxps://crystalxrat[.]net/api/ws` |
| **Triage** | 10/10 -- [260511-xzhpaacw3l](https://tria.ge/260511-xzhpaacw3l) |

Go RAT delivered as `NursultanCracked.exe`. Three-stage loader unpacks from RCDATA 970 (XOR -> ChaCha20 -> DEFLATE). Go payload uses AES-GCM string obfuscation, TLS WebSocket C2, and implements file manager, remote desktop, webcam, keylogger, clipboard, browser/messaging/wallet stealer, and system control.

## Detection

The rule targets the unpacked Go payload, not the native loader. It combines the Go build marker, WebSocket path, plaintext command fragments, and support markers from the persistence/build configuration. Build-specific values are used only as support, not as the primary detection condition.

The original loader encrypts the payload in its resource section, so it is not expected to match this rule.

## References

Full analysis in the [breach case directory](https://github.com/kirkderp/yara/tree/main/crystalx_go_rat).

### Hashes

| Artifact | SHA256 |
|---|---|
| `NursultanCracked.exe` (loader) | `34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094` |
| Unpacked Go payload | `a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a` |

### Network

| Indicator | Value |
|---|---|
| C2 endpoint | `crystalxrat[.]net:443` |
| WebSocket path | `hxxps://crystalxrat[.]net/api/ws` |
| Builder token | `X-Builder-Token: zenc0rn` |

### Host

| Indicator | Value |
|---|---|
| Scheduled task | `NvContainerTask_YBFZUW1U32` |
| Startup shortcut | `Windows Security Health Service.lnk` |
| Persistence path | `%LOCALAPPDATA%\Microsoft\DeviceMetadataStore\SecurityHealthSystray.exe` |
| Mutex | `Global\WinSecMutex_YBFZUW1U32` |
