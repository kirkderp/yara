# PoisonX WindowsTelemetry: sideload loader, BYOVD scheduler, and 10FX RAT core

**YARA Rule**: [PoisonX_WindowsTelemetry.yar](PoisonX_WindowsTelemetry.yar)

| | |
|---|---|
| **Family / case** | PoisonX WindowsTelemetry |
| **Rule scope** | Multi-layer case chain |
| **Malware type** | RAT |
| **Primary sample SHA256** | `0fb45474ca58bd67220f79b0e3b07f940270c371ba56e27d3e2b99bf4dbb5174` |
| **Known positive layers** | Source archives, VERSION.dll loader, cache blobs, decoded scheduler, decoded RAT core |
| **Triage** | [260519-tqveyabw9l](https://tria.ge/260519-tqveyabw9l), [260519-tqveyahs6t](https://tria.ge/260519-tqveyahs6t) |
| **Network** | `101.32.190[.]202:8080` |

PoisonX WindowsTelemetry is a sideloaded WindowsTelemetry chain built from a small `VERSION.dll` loader, rolling-XOR cache blobs, a decoded scheduler DLL, and a decoded RAT core. The scheduler branch is anchored on the `SetSuspendState` export, scheduler code bytes, WindowsTelemetry persistence, Defender blocklist tampering, and kernel callback removal strings. The RAT branch is anchored on the `StartPayload` export, plugin/config code bytes, the `10FX` protocol marker, task vocabulary, and plugin cache/request markers.

## Detection

YARA rule: [PoisonX_WindowsTelemetry.yar](PoisonX_WindowsTelemetry.yar)

The rule has four branches:

1. `VERSION.dll loader`: small PE32+ x64 DLL with loader PDB/build markers and the encoded `scheduler.cache` reference.
2. `raw cache blobs`: observed rolling-XOR cache headers for `scheduler.cache` and `cache.db`.
3. `decoded scheduler`: PE32+ x64 DLL with `SetSuspendState`, scheduler code bytes, WindowsTelemetry persistence, Defender blocklist tampering, BYOVD/callback-removal evidence.
4. `decoded RAT core`: PE32+ x64 DLL with `StartPayload`, RAT plugin/config code bytes, `10FX`, task vocabulary, and plugin cache/request strings.

Validation matched both loader DLLs, both cache blobs, the decoded scheduler, and the decoded RAT core.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| WindowsTelemetry ZIP | `0fb45474ca58bd67220f79b0e3b07f940270c371ba56e27d3e2b99bf4dbb5174` |
| Related RAR archive | `b892981af3ca699d13f07ddcf75c2df62c1543b071278b4cc1ac0993d8b9dc01` |
| VERSION.dll loader | `62431e499db7c6a02e93c5f9c79fbcff954144db1b016695d3f34f30c89d0b44` |
| VERSION.dll loader | `0ea1335fefc490622dae07b1a5936a539fa4152f89b64f4b270c8e23846deba6` |
| Decoded scheduler | `c07573810f5f4578315681ca9108ada8a56eefc1b4786b4e93b54b7abf4b028c` |
| Decoded RAT core | `0f841b7bddf9788589fce191bb3e7f9f52ec76adb67ff8c360618df8745ee320` |
| Embedded driver | `38c18db050b0b2b07f657c03db1c9595febae0319c746c3eede677e21cd238b0` |

### Network

| Type | Value | Context |
|---|---|---|
| IP:Port | `101.32.190[.]202:8080` | RAT C2 |

### Host

| Indicator | Value |
|---|---|
| Install path | `\Microsoft\WindowsTelemetry` |
| Service name | `WinHealthSvc` |
| Cache files | `scheduler.cache`, `cache.db` |
| Protocol marker | `10FX` |
| Plugin cache | `plugin.dat` |
| Driver evidence | `VulnerableDriverBlocklistEnable`, `PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine` |

## References

- Source report: https://x.com/mopisec
- Triage task: https://tria.ge/260519-tqveyabw9l
- Triage task: https://tria.ge/260519-tqveyahs6t
- YARA repository: https://github.com/kirkderp/yara
