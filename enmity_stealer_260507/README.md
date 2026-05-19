# Enmity Stealer: browser, wallet, and Discord token theft

**YARA Rule**: [Enmity_Stealer_260507.yar](Enmity_Stealer_260507.yar)

| | |
|---|---|
| **Family / case** | Enmity, submitted 2026-05-07 |
| **Rule scope** | Submitted x64 stealer build |
| **Malware type** | Stealer |
| **Primary sample SHA256** | `6d83880802874b883c8e6491fa5efac4898a3bbd59e0b861ecdf11a919a86188` |
| **Known positive layers** | Submitted PE |
| **Triage** | 10/10 -- [260507-exqyrsaz5n](https://tria.ge/260507-exqyrsaz5n) |
| **Network** | `futuregroupstar[.]lat:3000`, Discord webhook |

The submitted Enmity build is a 9 MB x64 PE with a stealer capability cluster for browser credentials, cryptocurrency wallets, Discord tokens, certificates, clipboard data, keystrokes, and process memory. The rule is not carried by the C2, PDB path, or webhook alone. It requires embedded Discord-token JavaScript, browser credential SQL, wallet collection paths, certificate-store imports, clipboard/keylogging imports, and process-memory imports.

## Detection

YARA rule: [Enmity_Stealer_260507.yar](Enmity_Stealer_260507.yar)

The rule has one branch:

1. `submitted stealer`: PE32+ x64 size and import guards plus Discord token JavaScript, browser credential SQL, wallet paths, certificate-store imports, clipboard/keylogging imports, process-memory imports, and one submitted-build support marker.

Validation matched the submitted Enmity binary. Nearby case samples stayed clean.

## IOC summary

### Hashes

| File | SHA256 |
|---|---|
| Submitted Enmity PE | `6d83880802874b883c8e6491fa5efac4898a3bbd59e0b861ecdf11a919a86188` |

### Network

| Type | Value | Context |
|---|---|---|
| WebSocket | `futuregroupstar[.]lat:3000` | C2 |
| URL | `hxxps://discord[.]com/api/webhooks/1493441198361153547/...` | Exfiltration webhook |

### Host

| Indicator | Value |
|---|---|
| Wallet archive | `wallets.zip` |
| Browser data | Firefox cookies, Chromium `Login Data` |
| Wallet targets | Exodus, Electrum, Wasabi, Coinomi, Monero |
| Certificate APIs | `PFXImportCertStore`, `CertOpenStore`, `CertEnumCertificatesInStore` |
| Clipboard/key APIs | `GetClipboardData`, `GetAsyncKeyState` |

## References

- Triage task: https://tria.ge/260507-exqyrsaz5n
- YARA repository: https://github.com/kirkderp/yara
