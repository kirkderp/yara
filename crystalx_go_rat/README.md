# CrystalX Go RAT: loader-wrapped Go RAT with WebSocket C2

**YARA Rule**: [CrystalX_Go_RAT.yar](CrystalX_Go_RAT.yar)

**Full writeup**: [derp.ca/research/crystalx-go-rat/](https://www.derp.ca/research/crystalx-go-rat/)

| Field | Value |
|---|---|
| Family | crystalx (Triage-assigned) |
| Loader SHA256 | `34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094` |
| Payload SHA256 | `a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a` |
| Type | PE32+ GUI (x86-64), native loader + Go payload |
| Submitted | 2026-05-11 |
| Triage | 10/10 (crystalx) -- [260511-xzhpaacw3l](https://tria.ge/260511-xzhpaacw3l) |
| C2 | `hxxps://crystalxrat[.]net/api/ws` |
| Related C2 | `crystalxrat[.]top` |
| Build ID | `YBFZUW1U32T` |

CrystalX is a Go RAT delivered through `NursultanCracked.exe`, a compact native loader with a large RCDATA payload. Resource `970` unwraps through position-dependent XOR, ChaCha20, and raw DEFLATE before the Go PE appears. The payload then hides operational strings behind AES-GCM and speaks TLS WebSocket C2 using `X-Builder-Token: zenc0rn`.

Kaspersky has reported CrystalX as a March 2026 malware-as-a-service RAT, originally seen as WebCrystal RAT before the rebrand. Public Triage results show a small visible CrystalX cluster across `crystalxrat[.]net` and `crystalxrat[.]top`.

## Detection

YARA rule: [CrystalX_Go_RAT.yar](CrystalX_Go_RAT.yar)

Full writeup: [derp.ca/research/crystalx-go-rat/](https://www.derp.ca/research/crystalx-go-rat/)

The rule has two branches:

1. **Loader branch**: submitted PE64 loader with RCDATA resource `970`, large embedded payload, resource-loading imports, PE mapping imports, and a loader PE-check byte sequence.
2. **Payload branch**: recovered Go payload with Go build marker, WebSocket path, remote desktop/webcam/file-manager/clipboard/stealer command fragments, and CrystalX build/support markers.

Validation matched the submitted loader, the recovered Go payload, and the runtime memory dump. The raw encrypted RCDATA blob and adjacent local sample corpus stayed clean during publication testing.

## IOC summary

### Hashes

| Type | Value |
|---|---|
| Loader SHA256 | `34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094` |
| Payload SHA256 | `a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a` |
| RCDATA 970 SHA256 | `8a6f8ef99384152df63a39b6ba9f08f0a1e9cc33b14319e8a1b184beb4a06cf7` |
| Runtime dump SHA256 | `2497e0aa88af681872194966bfc2bd67013ea75c96f4b5717abe4a4f43e69394` |

### Network

| Type | Value | Context |
|---|---|---|
| Domain | `crystalxrat[.]net:443` | Primary C2 observed in this sample |
| Domain | `crystalxrat[.]top` | Related CrystalX C2 from public Triage cluster |
| WebSocket path | `hxxps://crystalxrat[.]net/api/ws` | TLS WebSocket endpoint |
| Builder token | `X-Builder-Token: zenc0rn` | C2 request header |
| Nameservers | `braden.ns.cloudflare.com`, `teresa.ns.cloudflare.com` | Shared by `.net` and `.top` domains |

### Host

| Indicator | Value |
|---|---|
| Persistence path | `%LOCALAPPDATA%\Microsoft\DeviceMetadataStore\SecurityHealthSystray.exe` |
| Scheduled task | `NvContainerTask_YBFZUW1U32` |
| Startup shortcut | `Windows Security Health Service.lnk` |
| WMI filter | `Windows Security Health Service_Filter` |
| WMI consumer | `Windows Security Health Service_Consumer` |
| Firewall rules | `System Network Service`, `System Network Service Out` |
| Mutex | `Global\WinSecMutex_YBFZUW1U32` |
| Lock file | `%ProgramData%\GoogleUpdate\YBFZUW1U32T.lock` |

### Static keys

| Key | Use |
|---|---|
| `Hk4fOCLbqKFbbAxwyAcFKUKXK4iqVaMD` | AES-GCM string decrypt |
| `d01526bdaad75c24f94b80a6fde12b958078fa82beb4741e1ccdd8eb15564470` | ChaCha20 loader key |
| `598a7eeda372bc6d9992e03c` | ChaCha20 loader nonce |

## References

- [CrystalX: unpacking a Go RAT through three encrypted layers](https://www.derp.ca/research/crystalx-go-rat/)
- [Kaspersky: An analysis of CrystalX commercial RAT with prankware features](https://securelist.com/crystalx-rat-with-prankware-features/119283/)
