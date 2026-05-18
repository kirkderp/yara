import "pe"

/*
    Enmity Stealer -- Credential/Cryptocurrency/Discord Theft YARA Rule
    Author: derp.ca
    Date: 2026-05-18
    Source: https://github.com/kirkderp/yara

    C2: futuregroupstar[.]lat:3000
    Exfil: Discord webhook at discord[.]com/api/webhooks/1493441198361153547
    Target: credentials, cookies, crypto wallets, Discord tokens, certificates
    Browser targets: Chrome, Firefox, Opera, Brave, Edge, Yandex, Vivaldi
    Wallet targets: Exodus, Electrum, Wasabi, AtomicWallet, Coinomi, TrustWallet, Monero
    PDB: c:\Users\Iago Aquino Mendes\Documents\cht\rocket\Rocket\No

    Hashes:
        SHA256: 6d83880802874b883c8e6491fa5efac4898a3bbd59e0b861ecdf11a919a86188
        SHA1: 2fe66960338e62ccae38874109d637d94cebcde6
        MD5: 9678405134c1fc73623c84e679bd3213
*/

rule Enmity_Stealer_260507
{
    meta:
        id = "La4KjRLX2DRsgoSjQmiSU5"
        fingerprint = "3af678dcc3d37038937344e0b74f2f1e337497fd75937006"
        version = "1.0"
        date = "2026-05-18"
        modified = "2026-05-18"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        source = "https://github.com/kirkderp/yara"
        author = "derp.ca"
        description = "Enmity stealer rule targeting WebSocket C2, Discord webhook exfil, embedded Discord token JavaScript, browser credential SQL, wallet paths, and certificate theft imports."
        category = "MALWARE"
        malware = "ENMITY"
        malware_type = "STEALER"
        mitre_att = "T1055.012|T1555.003|T1115|T1056.001"
        reference = "https://github.com/kirkderp/yara"
        triage_score = 10
        triage_description = "Enmity stealer credential, wallet, Discord token, certificate, clipboard, and keylogging rule."
        yarahub_uuid = "83485cf8-0e48-48a2-bcca-01dbe4df76c1"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "9678405134c1fc73623c84e679bd3213"

    strings:
        $s_pdb = "c:\\Users\\Iago Aquino Mendes\\Documents\\cht\\rocket\\Rocket\\No" ascii
        $s_ws_c2 = "ws://futuregroupstar.lat:3000" ascii
        $s_webhook_path = "1493441198361153547/LOz3gDlrs_vBJI_Lp8X5EM7w-kDqeFhbkWBM9NJSSCbnu_P37n3e0Mza2DZu97WaNnsL" ascii
        $s_js_cached = "cachedToken" ascii
        $s_js_userinfo = "getUserInfo" ascii
        $s_js_usercache = "userCache" ascii
        $s_js_webhook = "const webhook = '" ascii
        $s_sql_cookies = "SELECT host, path, isSecure, expiry, name, value FROM moz_cookies" ascii
        $s_sql_logins = "SELECT origin_url, username_value, password_value FROM logins" ascii
        $s_wallet_zip = "\\wallets.zip" ascii
        $s_wallet_exodus = "\\Exodus\\exodus.wallet" ascii
        $s_wallet_wasabi = "\\WalletWasabi\\Client\\Wallets" ascii
        $s_wallet_electrum = "\\Electrum\\wallets" ascii
        $s_wallet_coinomi = "\\Coinomi\\Coinomi\\wallets" ascii
        $s_wallet_monero = "\\Monero\\wallets" ascii

    condition:
        uint16(0) == 0x5A4D and
        pe.machine == pe.MACHINE_AMD64 and
        filesize > 8MB and filesize < 10MB and
        (
            (
                all of ($s_ws_c2, $s_pdb, $s_webhook_path) and
                pe.imports("CRYPT32.dll", "PFXImportCertStore") and
                pe.imports("USER32.dll", "GetAsyncKeyState")
            )
            or
            (
                all of ($s_js_*) and
                2 of ($s_wallet_*) and
                1 of ($s_sql_*) and
                pe.imports("CRYPT32.dll", "CertOpenStore") and
                pe.imports("CRYPT32.dll", "CertEnumCertificatesInStore") and
                pe.imports("USER32.dll", "GetClipboardData") and
                pe.imports("KERNEL32.dll", "CreateToolhelp32Snapshot") and
                2 of ($s_wallet_*)
            )
        )
}
