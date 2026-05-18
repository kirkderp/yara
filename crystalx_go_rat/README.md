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

The rule matches the submitted loader and the recovered Go payload. The loader branch keys on the PE64 resource-loading stub, resource ID `970`, the large RCDATA payload, and the import set used to load and map the embedded payload. The payload branch keys on the Go build marker, WebSocket path, command fragments, and persistence/build markers.

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
