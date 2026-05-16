# Vidar v1.5 in Go: same family, new language, heavy sandbox checks

**YARA Rule**: [Vidar_v1_5_Go.yar](Vidar_v1_5_Go.yar)

**Full writeup**: [derp.ca/research/vidar-go-sandbox-dead-drop/](https://www.derp.ca/research/vidar-go-sandbox-dead-drop/)

| Field | Value |
|---|---|
| SHA256 | `2995ffb73342453b258926ec865c724e3567eee1bb8eb35d61796ee0c4f25105` |
| Type | PE32+ GUI (x86-64), Go 1.25.4 |
| Size | 7,211,168 bytes |
| Triage | 10/10 (vidar) |
| Submitted | 2026-05-13 |
| Family rule | Vidar_v1_5 |
| Botnet ID | `702ef1b4007f07887e9faaee0667b50b` |
| Version | 1.5 |

Vidar is a name most infostealer trackers know well -- an Arkei descendant that has been snatching browser credentials and crypto wallets since 2018. It usually ships as a .NET binary or a C++ PE. The v1.5 sample we pulled from Triage on May 13, 2026 is neither. It is a 7 MB Go 1.25.4 native PE with a twelve-category sandbox scoring system, dead-drop C2 via Telegram and Steam profile pages, and enough crypto primitives to make a librarian blush.

Previous coverage of Go-based Vidar builds (Datadog's MUT-4831, Malwarebytes March 2026) established the Telegram/Steam C2 discovery pattern. Our sample follows the same strategy but belongs to a separate build track: unique botnet ID, separate C2 IP at a Hetzner box in Finland, and its own Telegram handle and Steam profile.

## Not your father's .NET stealer

Capa identified a collection of crypto primitives that go beyond what a typical Vidar build needs for config decryption alone:

- AES-NI (hardware aesenc instructions)
- ChaCha20 / Salsa20 sigma constant
- RC4 PRGA implementation
- Base64 encoding
- MurmurHash3

The binary also walks PE export tables and enumerates PE sections at runtime -- capability profiles typical of reflective loading or injection, not passive data theft. Rbin confirmed the sample resolves native APIs dynamically via GetProcAddress against KERNEL32.DLL, NTDLL.DLL, WINHTTP.DLL, CRYPT32.DLL, and BCRYPT.DLL, among others.

## Twelve categories of "not a sandbox"

12 checks across multiple categories, requiring 6 out of 9 core checks to pass or the binary self-terminates.

| Check | What it tests |
|---|---|
| internet | Network connectivity |
| debugger | Debugger present |
| peb_flags | PEB BeingDebugged flag |
| cpus | CPU core count |
| rdtsc | RDTSC timing delta |
| modules | Loaded module inspection |
| ram | Physical RAM size (GB) |
| disk | Disk size (GB) |
| user | Username blacklist (John, sandbox, WDAGUtilityAccount) |
| av_sandbox | AV presence detection |
| pc | Hostname blacklist (JOHN-PC, SANDBOX) |
| uptime | System uptime |

Plus `NtSetInformationThread` with `HideFromDebugger`.

## AV kill list

AvastSvc.exe, aswEngSrv.exe, AvastUI.exe, avgcsrva.exe, avgsvc.exe, avgui.exe, ekrn.exe (ESET), egui.exe, essod.exe, PccNTMon.exe (Trend Micro), TMBMSRV.exe, TmListen.exe, NTRTScan.exe, TmCCSF.exe, coreServiceShell.exe (McAfee), avp.exe (Kaspersky), avpui.exe, kavfs.exe, MsMpEng.exe (Defender), MpCmdRun.exe, bdagent.exe (BitDefender), bdservicehost.exe, vsserv.exe, NortonSecurity.exe, nsWscSvc.exe, ccSvcHst.exe, MBAMService.exe, mbamtray.exe.

Notable: Avast-specific hook checks (`aswhook.dll`) and Kaspersky filesystem driver (`kavfs.exe`).

## Process injection

- NtCreateThreadEx, NtOpenProcess, NtWriteVirtualMemory, NtAllocateVirtualMemory, NtProtectVirtualMemory, NtReadVirtualMemory
- VirtualAllocEx, WriteProcessMemory, VirtualProtect, CreateProcessA, ResumeThread
- CreateToolhelp32Snapshot, Process32First, Process32Next

Consistent with Vidar's technique of launching browsers in debug mode and injecting shellcode to steal encryption keys from process memory.

## Dead drop C2 via Telegram and Steam

Rbin emulation (125 seconds, 59 million instructions, 2,437 API calls) confirmed the live C2 protocol using WinHTTP directly -- not Go's standard http library.

**Primary C2**: Raw IP HTTPS to `135.181.237.59:443` (Hetzner, Finland). Multipart form-data POST with fields `hwid` and `build_id`.

**Dead drop URLs**: Telegram and Steam profile pages that serve as a dead-drop resolver for active C2 address publication.

Dead drops:
- `https://telegram.me/hgo9tx`
- `https://steamcommunity.com/profiles/76561198707628078`

Two User-Agent strings:
- `Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0` (dead drops)
- `Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) Gecko/20100101 Firefox/153.0` (C2)

Dead drop logging format: `"Dead drop: %s (sw: %s)"`.

## Config

```
version: 1.5
family: vidar
botnet: 702ef1b4007f07887e9faaee0667b50b
c2:
  - https://telegram.me/hgo9tx
  - https://steamcommunity.com/profiles/76561198707628078
user_agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:140.0) Gecko/20100101 Firefox/140.0
```

## Detection

YARA rule: [Vidar_v1_5_Go.yar](Vidar_v1_5_Go.yar)

Full writeup: [derp.ca/research/vidar-go-sandbox-dead-drop/](https://www.derp.ca/research/vidar-go-sandbox-dead-drop/)

## IOC summary

### Hashes

| Type | Value |
|---|---|
| SHA256 | `2995ffb73342453b258926ec865c724e3567eee1bb8eb35d61796ee0c4f25105` |
| SHA1 | `488d2dd8768e3b804179e7f0cdcebd0a7eec52b3` |
| MD5 | `87332fcdf79e1c0bfb7713e9a52c0313` |

### Network

| Type | Value | Context |
|---|---|---|
| IP | `135.181.237.59:443` | Vidar C2 (Hetzner, Finland) |
| URL | `https://telegram.me/hgo9tx` | Dead drop resolver |
| URL | `https://steamcommunity.com/profiles/76561198707628078` | Dead drop resolver |

### Behavioural

| Technique | Detail |
|---|---|
| Anti-debug | NtSetInformationThread HideFromDebugger |
| Sandbox evasion | 12-category scoring (6/9 to pass) |
| Process injection | NtCreateThreadEx, NtWriteVirtualMemory, VirtualAllocEx |
| C2 discovery | Dead drop resolver via Telegram/Steam profile pages |
| Crypto | AES-NI, ChaCha20, RC4, Base64, MurmurHash3 |
| Language | Go 1.25.4 native PE |

---

If you operate a threat intelligence platform or run Triage infrastructure and can share data, reach out. Additional sample visibility directly sharpens the tracking.
