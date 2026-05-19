# CrystalX Go RAT: RCDATA loader and recovered Go payload

**YARA Rule**: [CrystalX_Go_RAT.yar](CrystalX_Go_RAT.yar)

**Full writeup**: [derp.ca/research/crystalx-go-rat/](https://www.derp.ca/research/crystalx-go-rat/)

| | |
|---|---|
| **Family / case** | CrystalX, Triage-assigned |
| **Rule scope** | Submitted loader and recovered Go payload |
| **Malware type** | RAT |
| **Primary sample SHA256** | `34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094` |
| **Known positive layers** | Loader, recovered Go payload, runtime dump |
| **Triage** | 10/10 -- [260511-xzhpaacw3l](https://tria.ge/260511-xzhpaacw3l) |
| **Network** | `crystalxrat[.]net:443` |

CrystalX is delivered as a compact native x64 loader with a large RCDATA resource. Resource `970` unwraps into a Go payload that uses a WebSocket path, remote desktop/webcam/file-manager command vocabulary, persistence markers, and build support strings. The loader branch is anchored on resource structure, loader imports, and a PE-check code byte sequence; the payload branch is scoped to the recovered Go payload and runtime dump.

## Detection

YARA rule: [CrystalX_Go_RAT.yar](CrystalX_Go_RAT.yar)

The rule has two branches:

1. `loader`: PE32+ x64 loader with 11 sections, large RCDATA resource `970`, resource-loading imports, PE mapping imports, and a loader PE-check byte sequence.
2. `recovered payload`: Go PE with Go build marker, WebSocket path, remote desktop/webcam/file-manager/clipboard/stealer command vocabulary, and two build support markers.

Validation matched the submitted loader, recovered Go payload, and runtime dump. The raw encrypted RCDATA blob stayed clean.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| Loader | `34b84db8f10d34f711bb242b21bdf662ee489dcd0e9c23b9cc95240d324bb094` |
| Recovered Go payload | `a9340c46243f5d2b00e30ea649bd14fc146ebbb42e43dbe45f5ee0cc9fc9227a` |
| Runtime dump | `2497e0aa88af681872194966bfc2bd67013ea75c96f4b5717abe4a4f43e69394` |
| RCDATA 970 blob | `8a6f8ef99384152df63a39b6ba9f08f0a1e9cc33b14319e8a1b184beb4a06cf7` |

### Network

| Type | Value | Context |
|---|---|---|
| Domain | `crystalxrat[.]net:443` | Primary C2 |
| URL path | `/api/ws` | WebSocket endpoint |
| Domain | `crystalxrat[.]top` | Related CrystalX C2 from public Triage cluster |
| Header | `X-Builder-Token: zenc0rn` | C2 request header |

### Host

| Indicator | Value |
|---|---|
| Persistence path | `%LOCALAPPDATA%\Microsoft\DeviceMetadataStore\SecurityHealthSystray.exe` |
| Scheduled task prefix | `NvContainerTask_` |
| Mutex prefix | `Global\WinSecMutex_` |
| Lock file suffix | `.lock` |
| Build ID | `YBFZUW1U32T` |
| String decrypt key | `Hk4fOCLbqKFbbAxwyAcFKUKXK4iqVaMD` |

## References

- Derp writeup: https://www.derp.ca/research/crystalx-go-rat/
- Triage task: https://tria.ge/260511-xzhpaacw3l
- Kaspersky CrystalX analysis: https://securelist.com/crystalx-rat-with-prankware-features/119283/
- YARA repository: https://github.com/kirkderp/yara
