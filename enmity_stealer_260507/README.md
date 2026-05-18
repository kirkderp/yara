# Enmity Stealer: browser, wallet, and Discord theft

**YARA Rule**: [Enmity_Stealer_260507.yar](Enmity_Stealer_260507.yar)

| Field | Value |
|---|---|
| SHA256 | `6d83880802874b883c8e6491fa5efac4898a3bbd59e0b861ecdf11a919a86188` |
| Type | PE32+ GUI (x86-64), MSVC C++ |
| Size | 9,067,008 bytes |
| PDB | `c:\Users\Iago Aquino Mendes\Documents\cht\rocket\Rocket\No` |
| Triage | 10/10 (enmity) |
| Submitted | 2026-05-07 |
| Family rule | Enmity_Stealer_260507 |
| C2 | `futuregroupstar[.]lat:3000` |
| Exfil | Discord webhook |

Triage assigned the family label "Enmity" to a sample it saw on May 7, 2026. The static engine extracted a Discord webhook and WebSocket C2 endpoint, and Triage's built-in signatures flagged the binary for browser references, wallet extension IDs, Discord URLs, and credential-store SQL queries. Dynamic execution was less productive -- both sandbox runs scored 1 and showed no C2 contact.

## What it steals

### Browsers (7 targets)

Browser credential theft via SQLite queries against Firefox profiles and Chrome-based `Login Data` databases:

```
SELECT host, path, isSecure, expiry, name, value FROM moz_cookies
SELECT origin_url, username_value, password_value FROM logins
```

| Browser | Discovery Pattern |
|---|---|
| Chrome | `chrome.exe`, `chrome` |
| Firefox | `\Mozilla\Firefox`, `# Firefox Cookies` |
| Edge | `msedge.exe`, registry uninstall paths |
| Brave | `brave.exe`, `brave` |
| Opera | (string present) |
| Yandex | `\Yandex\YandexBrowser\User Data` |
| Vivaldi | `\Vivaldi\User Data` |

Cookies, saved passwords, and session tokens are written to `Cookies.txt`, `Passwords.txt`, and `tokens.txt`.

### Cryptocurrency wallets (8 targets)

Wallet files are located by path and zipped into `wallets.zip`:

| Wallet | Path Pattern |
|---|---|
| Exodus | `\Exodus\exodus.wallet` |
| Electrum | `\Electrum\wallets` |
| Wasabi Wallet | `\WalletWasabi\Client\Wallets` |
| AtomicWallet | `AtomicWallet` (desktop + extension) |
| Coinomi | `\Coinomi\Coinomi\wallets` |
| TrustWallet | `TrustWallet` (browser extension context) |
| Monero | `\Monero\wallets`, `MyMonero` |
| Wallet output | `\wallets.zip` |

### Discord token theft (embedded JavaScript)

Full JavaScript token grabber embedded in the binary `.rdata`:

```javascript
let cachedToken = null;
let userCache = {};

function sendData(embedData) {
    const payload = JSON.stringify({ embeds: [embedData] });
    // POST to Discord webhook via https.request
}

function getUserInfo(token, callback) {
    if (userCache[token]) {
        callback(userCache[token]);
        return;
    }
    // GET discord[.]com/api/v10/users/@me with Authorization header
}
```

The webhook path is hardcoded in the JS context for direct exfiltration.

### Certificate theft

The import table includes `PFXImportCertStore`, `CertOpenStore`, `CertEnumCertificatesInStore`, `CertFindCertificateInStore` -- covering the full path from enumerating system certificate stores to importing PFX/PKCS12 blobs. This is consistent with stealing client authentication certificates (smart card tokens, enterprise VPN certs, S/MIME signing keys).

### Clipboard monitoring and keylogging

| API | Purpose |
|---|---|
| `GetClipboardData` / `SetClipboardData` | Read and write clipboard contents |
| `OpenClipboard` / `CloseClipboard` | Clipboard session management |
| `EmptyClipboard` | Clear clipboard after theft |
| `GetAsyncKeyState` / `GetKeyState` | Basic keystroke monitoring |

### Process enumeration and injection

| API | Purpose |
|---|---|
| `CreateToolhelp32Snapshot` | Enumerate running processes |
| `Module32Next` / `Process32Next` | Walk process and module lists |
| `ReadProcessMemory` / `WriteProcessMemory` | Cross-process memory access |
| `OpenProcess` | Open handles to target processes |

### DirectX overlay

The binary imports D3D11, D3DX9, D3DX11, and D3DCompiler -- likely for rendering a transparent overlay window (`SetLayeredWindowAttributes`, `DwmExtendFrameIntoClientArea`).

## C2 infrastructure

| Detail | Value |
|---|---|
| WebSocket C2 | `futuregroupstar[.]lat:3000` |
| Discord webhook | `hxxps://discord[.]com/api/webhooks/1493441198361153547/...` |
| User-Agent | `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36` |

Both C2 endpoints were extracted by Triage's static config analysis and confirmed locally. The WebSocket C2 domain (`futuregroupstar[.]lat`) did not resolve at analysis time (2026-05-18) and the webhook path was not probed.

## Developer signature

PDB path embedded in the PE:
```
c:\Users\Iago Aquino Mendes\Documents\cht\rocket\Rocket\No
```

Can be used to cluster future samples from the same build chain.

## Detection

YARA rule: [Enmity_Stealer_260507.yar](Enmity_Stealer_260507.yar)

Custom rules are deployed to [YARAify](https://yaraify.abuse.ch/) and [Triage](https://tria.ge).

The YARA rule uses two-tier logic, both guarded by PE32+ x64 size bounds and imported capability evidence:

1. **Submitted variant branch**: C2 string, PDB path (`Iago Aquino Mendes...`), full Discord webhook path, certificate theft import, and keylogging import.
2. **Stealer module branch**: Discord JS grabber functions (`cachedToken` + `getUserInfo` + `userCache` + `const webhook = '`), wallet paths, browser credential SQL, certificate-store imports, clipboard import, and process enumeration import.

Validation matched the submitted Enmity binary. Adjacent local breach corpus samples stayed clean.

## IOC summary

### Hashes

| Type | Value |
|---|---|
| SHA256 | `6d83880802874b883c8e6491fa5efac4898a3bbd59e0b861ecdf11a919a86188` |
| SHA1 | `2fe66960338e62ccae38874109d637d94cebcde6` |
| MD5 | `9678405134c1fc73623c84e679bd3213` |

### Network

| Type | Value | Context |
|---|---|---|
| Domain | `futuregroupstar[.]lat:3000` | WebSocket C2 |
| URL | `hxxps://discord[.]com/api/webhooks/1493441198361153547/...` | Exfil webhook |

### Files written at runtime

| File | Content |
|---|---|
| `Cookies.txt` | Browser cookies |
| `Passwords.txt` | Saved credentials |
| `tokens.txt` | Session tokens |
| `wallets.zip` | Cryptocurrency wallet files |

### Capability summary

| Technique | APIs / Strings |
|---|---|
| Browser credential theft | `moz_cookies`, `logins`, `Login Data` SQL queries |
| Discord token theft | Embedded JS: `getUserInfo`, `cachedToken`, webhook POST |
| Crypto wallet theft | 8 wallets zipped to `wallets.zip` |
| Certificate theft | `PFXImportCertStore`, `CertOpenStore` |
| Clipboard monitoring | `GetClipboardData`, `SetClipboardData` |
| Keylogging | `GetAsyncKeyState`, `GetKeyState` |
| Process injection | `ReadProcessMemory`, `WriteProcessMemory` |
| DirectX overlay | D3D11, D3DX9, D3DX11, `DwmExtendFrameIntoClientArea` |

### YARA Rule Metadata

```
rule Enmity_Stealer_260507
{
    meta:
        id = "La4KjRLX2DRsgoSjQmiSU5"
        version = "1.0"
        date = "2026-05-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "derp.ca"
        category = "MALWARE"
        malware = "ENMITY"
        malware_type = "STEALER"
        mitre_att = "T1055.012|T1555.003|T1115|T1056.001"
        triage_score = 10
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
}
```

---

Additional samples sharing the PDB path or wallet/browser target list are useful clustering points for this rule.
