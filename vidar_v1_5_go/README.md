# Vidar v1.5 in Go: submitted build and memory/runtime indicators

**YARA Rule**: [Vidar_v1_5_Go.yar](Vidar_v1_5_Go.yar)

**Full writeup**: [derp.ca/research/vidar-go-sandbox-dead-drop/](https://www.derp.ca/research/vidar-go-sandbox-dead-drop/)

| | |
|---|---|
| **Family / case** | Vidar v1.5 Go |
| **Rule scope** | Submitted build plus memory/runtime indicators |
| **Malware type** | Infostealer |
| **Primary sample SHA256** | `2995ffb73342453b258926ec865c724e3567eee1bb8eb35d61796ee0c4f25105` |
| **Known positive layers** | Submitted PE, runtime string capture |
| **Triage** | 10/10 -- [260513-xe8pzahw7l](https://tria.ge/260513-xe8pzahw7l) |
| **Network** | `135.181.237[.]59:443`, Telegram and Steam dead drops |

This Vidar sample is a Go 1.25.4 x64 PE with runtime evidence for sandbox scoring, Telegram/Steam dead-drop discovery, and multipart exfiltration. The on-disk branch is submitted-build scoped because the static match is carried by Go build metadata and native API layout. The memory/runtime branches cover the twelve-category sandbox scoring strings, dead-drop/exfil fields, botnet ID, and AV process enumeration.

## Detection

YARA rule: [Vidar_v1_5_Go.yar](Vidar_v1_5_Go.yar)

The rule has five branches:

1. `submitted build`: PE32+ x64 Go binary with Go build ID, Go version, native API helper names, and DLL-name layout.
2. `submitted build API layout`: Go build metadata plus native wait/random/timer API names.
3. `sandbox scoring`: runtime strings for the sandbox scoring categories plus exfil/dead-drop markers.
4. `dead-drop exfil`: Telegram/Steam/C2 markers with multipart `hwid` and `build_id` fields.
5. `botnet AV list`: botnet marker plus AV process enumeration strings.

Validation matched the submitted Vidar binary. Memory/runtime indicators were confirmed in the case runtime string capture.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| Submitted Vidar PE | `2995ffb73342453b258926ec865c724e3567eee1bb8eb35d61796ee0c4f25105` |

### Network

| Type | Value | Context |
|---|---|---|
| IP:Port | `135.181.237[.]59:443` | C2 |
| URL | `hxxps://telegram[.]me/hgo9tx` | Dead-drop resolver |
| URL | `hxxps://steamcommunity[.]com/profiles/76561198707628078` | Dead-drop resolver |

### Host

| Indicator | Value |
|---|---|
| Version | `1.5` |
| Botnet ID | `702ef1b4007f07887e9faaee0667b50b` |
| Sandbox scoring labels | `internet`, `debugger`, `peb_flags`, `cpus`, `rdtsc`, `modules`, `ram`, `disk`, `user`, `av_sandbox`, `pc`, `uptime` |
| Exfil fields | `hwid`, `build_id` |
| AV process examples | `AvastSvc.exe`, `ekrn.exe`, `MsMpEng.exe`, `bdagent.exe`, `MBAMService.exe` |

## References

- Derp writeup: https://www.derp.ca/research/vidar-go-sandbox-dead-drop/
- Triage task: https://tria.ge/260513-xe8pzahw7l
- YARA repository: https://github.com/kirkderp/yara
