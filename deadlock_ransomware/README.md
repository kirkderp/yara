# DeadLock ransomware

**YARA Rule**: [DeadLock_Ransomware.yar](DeadLock_Ransomware.yar)

| | |
|---|---|
| **Family / case** | DeadLock ransomware, submitted 2026-06-21 |
| **Rule scope** | Submitted 32-bit Windows ransomware build |
| **Malware type** | Ransomware |
| **Primary sample SHA256** | `c9cc95ff8f2998229394dfd31c2bd6b723e826a3ca5e008d2b5be19ba419ae2c` |
| **Known positive layers** | Submitted PE |
| **Triage** | 10/10 -- [260621-velt4aes3r](https://tria.ge/260621-velt4aes3r) |
| **Network** | Embedded Session messenger recovery page with public Polygon RPC fallback hosts |

The submitted DeadLock sample is a 257 KB unsigned PE32 console executable. Static analysis shows a Rust-linked ransomware build with direct `NtReadFile` / `NtWriteFile` imports, dynamically resolved Windows APIs, `.dlock` extension handling, `RECOVERY_CHAT` / `HOW_RECOVER` recovery artifacts, and an embedded HTML chat page.

The rule avoids the embedded Session contact ID and contract value. Detection is carried by the DeadLock note and HTML template, static recovery filenames, Windows disruption API-name clusters, process/service/path exclusion config, and code bytes from the config parser and recovery setup paths.

## Detection

YARA rule: [DeadLock_Ransomware.yar](DeadLock_Ransomware.yar)

The rule has one branch:

1. `submitted ransomware`: PE32 i386 size/section/import guards plus DeadLock ransom-note strings, HTML recovery template strings, `.dlock` and recovery filename artifacts, privilege/event-log/service-control/process-control API-name clusters, static exclusion config, Rust/ChaCha support markers, and one code-byte anchor from the config parser or recovery setup logic.

Validation matched the submitted DeadLock binary. Campaign-changeable Session contact material is not required by the rule.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| Submitted DeadLock PE | `c9cc95ff8f2998229394dfd31c2bd6b723e826a3ca5e008d2b5be19ba419ae2c` |

### Network

| Type | Value | Context |
|---|---|
| Service | Session messenger | Recovery-chat contact path embedded in the HTML note |
| Host | `polygon-bor-rpc[.]publicnode[.]com` | Public Polygon RPC fallback in embedded recovery page |
| Host | `polygon[.]drpc[.]org` | Public Polygon RPC fallback in embedded recovery page |
| Host | `polygon-pokt[.]nodies[.]app` | Public Polygon RPC fallback in embedded recovery page |
| Host | `polygon-rpc[.]com` | Public Polygon RPC fallback in embedded recovery page |
| Host | `1rpc[.]io/matic` | Public Polygon RPC fallback in embedded recovery page |
| Host | `polygon[.]meowrpc[.]com` | Public Polygon RPC fallback in embedded recovery page |

### Host

| Indicator | Value |
|---|---|
| Encrypted file extension | `.dlock` |
| Recovery artifacts | `RECOVERY_CHAT`, `RECOVERY_CHAT.{_UID}.HTML`, `HOW_RECOVER` |
| Public desktop target | `Users\Public\Desktop\` |
| Ransom note marker | `Your infrastructure DeadLocked All Files stolen and encrypted` |
| Privilege strings | `SeDebugPrivilege`, `SeRestorePrivilege`, `SeBackupPrivilege`, `SeTakeOwnershipPrivilege` |
| Event log APIs | `EvtOpenChannelEnum`, `EvtNextChannelPath`, `ClearEventLogW` |
| Service APIs | `OpenSCManagerA`, `EnumServicesStatusExW`, `ControlService`, `ChangeServiceConfigW` |
| Process APIs | `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next`, `TerminateProcess` |

## References

- Triage task: https://tria.ge/260621-velt4aes3r
- YARA repository: https://github.com/kirkderp/yara
