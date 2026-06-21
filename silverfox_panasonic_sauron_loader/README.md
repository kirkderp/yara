# SilverFox-style Panasonic/Sauron loader chain

**YARA Rule**: [SilverFox_Panasonic_Sauron_Loader.yar](SilverFox_Panasonic_Sauron_Loader.yar)

**Full writeup**: [derp.ca/research/silverfox-panasonic-sauron-loader-chain/](https://www.derp.ca/research/silverfox-panasonic-sauron-loader-chain/)

| | |
|---|---|
| **Family / case** | SilverFox-style Panasonic/Sauron loader chain |
| **Rule scope** | Multi-layer case chain from submitted wrapper through decoded Sauron stage |
| **Malware type** | Loader / RAT chain |
| **Primary sample SHA256** | `200d9f5d041c870e69f73da32c753a69096742c33e2dab65299767ac31578267` |
| **Known positive layers** | Submitted wrapper, decoded heap payload, first-bucket carriers, `UxEnhance64.dll`, `msadox.tb`, `adoresd.dat`, `RPCScheduleTask.dll`, `adoresd.dll`, populated bridge, `image.dll`, `rundll32.dat` |
| **Triage** | 10/10 -- [260619-v47g4ah12k](https://tria.ge/260619-v47g4ah12k) |
| **Network** | `jun616[.]oss-cn-beijing[.]aliyuncs[.]com`, `26nn[.]oss-cn-hangzhou[.]aliyuncs[.]com`, `47[.]239[.]170[.]54`, `gqsqoq[.]net` |

The submitted file is a Panasonic PC Notification wrapper with an early staged loader. The malicious path allocates executable memory, copies encoded bytes from a large `.data` section, decodes a heap payload, reconstructs an Alibaba OSS URL, and pulls image-named carrier files.

The chain then moves through a signed Ux side-load host, `UxEnhance64.dll`, `msadox.tb`, `adoresd.dat`, an `adoresd.dll` bridge, a Philips `D1IQf1.exe` / `XPSPLOG.dll` cluster, and a final `rundll32.dat!Edge` Sauron stage. The rule is case-chain scoped. It targets stable structure, export/import combinations, carrier trailer grammar, and code-referenced strings from decoded artifacts.

## Detection

YARA rule: [SilverFox_Panasonic_Sauron_Loader.yar](SilverFox_Panasonic_Sauron_Loader.yar)

The rule has thirteen branches:

1. `submitted wrapper`: PE32+ x64 Panasonic wrapper with a large `.data` payload area, staged-copy allocator bytes, marker-derived host material, and the encoded staged-buffer prefix.
2. `decoded heap payload`: recovered raw payload with Defender-exclusion PowerShell strings, `checktime.vbs`, and `runas`.
3. `first-bucket JPEG carriers`: observed `a.gif`, `b.gif`, `c.gif`, and `d.gif` carrier files using exact case sizes and the `a0 03 00 00 45` EOF trailer.
4. `s.jpg carrier`: PNG carrier with the observed `40 21 00 00 a8` EOF trailer.
5. `UxEnhance64.dll`: side-loaded x64 DLL with `?EnableUxEnhance@@YA_NXZ` / `?DisableUxEnhance@@YA_NXZ`, `ReadFile`, and the protected `.Ias`, `.LUx`, and `.\OF` section names.
6. `msadox.tb`: SQLite-looking opaque material with the marker used before RC4 shellcode decode.
7. `adoresd.dat`: PNG carrier for the sparse `adoresd.dll` bridge.
8. `RPCScheduleTask.dll`: recovered `s.jpg` payload exporting `VirtuOne` and importing Task Scheduler RPC functions from `RPCRT4.dll`.
9. `adoresd.dll`: sparse bridge DLL exporting `DelegateEnSerialization`.
10. `populated bridge`: runtime-populated Ux bridge image with `Task1`, Hangzhou OSS / `drops` fragments, `GetData`, and `adoresd` strings.
11. `raw D1 image.dll`: raw decoded Philips `image.dll` with `PhilipsCoInitialize`, distinctive imports, and packed-looking section names.
12. `rebuilt D1 image.dll`: rebuilt Philips `image.dll` memory image with D1 path, `Task1`, `ranchserv.jpg`, and `XPSPLOG.dll` evidence.
13. `rundll32.dat!Edge`: Sauron stage with service, WinINet, service-control, cleanup, firewall-off, and BOOTSECT evidence.

Validation matched the known case artifacts listed above. The signed `UxEnhanceHost` carrier output, `ranchserv.jpg` driver material, and unrelated third-party packer/PEiD rules in the analysis workspace are not used as public detection anchors.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| Submitted `ainstaller-86533005.exe` | `200d9f5d041c870e69f73da32c753a69096742c33e2dab65299767ac31578267` |
| Encoded staged buffer | `415611a746fc72025f206164eb61a966125a76125ab1c84ec37e159dfbc8d6b3` |
| Decoded heap payload | `679921a7373fc0a77d60416e3f7ce4454dfd394c12d9c0387be9538b8f030e02` |
| Raw `a.gif` carrier | `6349d18308f458ed290913068752471c453f1c9bbd472a73e9f92b444718bd4d` |
| Raw `b.gif` carrier | `c2ffcb613698ba2c74614b993f550073f6dd2ba2f1c3f120d68959aa142c78ad` |
| Raw `c.gif` carrier | `c0627c59e27a670503683d2c5c117e126f4969144815317540895066c819b6f6` |
| Raw `d.gif` carrier | `ab432ec0e732c20c99b6413e7ab9d0ac18bcd5d405a6266ff0c1afced64cb165` |
| Raw `s.jpg` carrier | `71369dd8ef596d4eefaf21b831dc87f78eeaf2c3436eb95c24981a6d39151dd7` |
| `UxEnhance64.dll` | `cc6ae6f13d33a7313295ae00a6b0503adc277289fbe615eaf48b6a30ce09f11c` |
| `msadox.tb` | `d14e3e61957ba142d64830b63418ce816e76e4c25449539a5cebb5bcd5f84c7f` |
| `adoresd.dat` | `1a9804780f9b96018961a4100b3ff70d6440a2677ce996209c6be0d581b4677f` |
| `RPCScheduleTask.dll` | `a1e68e7adc5597eae23a6590f1ac345f796abebceb91afcc0f2dd97cc0622740` |
| Decoded `adoresd.dll` | `aaa13e34e7c45dc49552e843ee8b611b2373959d8a7cc23265abc353d76235ba` |
| Populated bridge image | `09ae57f0e6ffa1abed9b868e6693cdba846111b24bc50fc278f3017de7d5c943` |
| `image.dll` | `96aee41363c08acf6a6230d1dda5f7e7dae9f78952993b70a9c8c4949c81bb22` |
| `rundll32.dat` | `4f67662ae285337b17e537147e4783a6f307b25d61b362e7908b2595c4188f2a` |

### Network

| Type | Value | Context |
|---|---|---|
| URL | `hxxps://jun616[.]oss-cn-beijing[.]aliyuncs[.]com/tad` | First reconstructed OSS index |
| Host | `26nn[.]oss-cn-hangzhou[.]aliyuncs[.]com` | Later bridge-correlated OSS host |
| Path | `/drops.jpg` | Later bridge-correlated object path |
| User-Agent | `GetData` | Later bridge-correlated request material |
| IP | `47[.]239[.]170[.]54` | Runtime-loaded `rundll32.dat` config |
| Domain | `gqsqoq[.]net` | Runtime-loaded `rundll32.dat` config |

### Host

| Indicator | Value |
|---|---|
| Panasonic visible identity | `PPcNotif.Provider.RequiredApp.exe` |
| Heap-payload VBS helper | `checktime.vbs` |
| Ux side-loaded DLL | `UxEnhance64.dll` |
| Opaque loader material | `msadox.tb`, `adoresd.dat` |
| RPC scheduler export | `VirtuOne` |
| Bridge export | `DelegateEnSerialization` |
| Bridge registry marker | `Software\ODBDC` |
| Defender task template | `Task1` |
| Philips side-load cluster | `D1IQf1.exe`, `XPSPLOG.dll`, `image.png`, `thumbs.db` |
| Driver materialization path | `C:\Windows\Temp\ranchserv.jpg` |
| Sauron service key | `Sauron` |
| Sauron stage | `rundll32.dat!Edge` |
| EdgeUpdate log path | `C:\ProgramData\Microsoft\EdgeUpdate\Log\` |
| BOOTSECT path | `C:\ProgramData\Microsoft\eHome\BOOTSECT.exe` |

## References

- Derp writeup: https://www.derp.ca/research/silverfox-panasonic-sauron-loader-chain/
- Triage task: https://tria.ge/260619-v47g4ah12k
- Huorong SilverFox report: https://www.huorong.cn/document/tech/vir_report/1772.html
- Picus Silver Fox medical-software report: https://www.picussecurity.com/resource/blog/silver-fox-apt-targets-public-sector-via-trojanized-medical-software
- ThreatBook Winos ecosystem report: https://threatbook.io/blog/silver-fox-not-an-organization-but-a-tool-uncovering-the-underground-ecosystem
- Fortinet Winos4.0 analysis: https://www.fortinet.com/it/blog/threat-research/threat-campaign-spreads-winos4-through-game-application
- YARA repository: https://github.com/kirkderp/yara
