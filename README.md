# 🔥 FirewallTester v3.0

Outil d'audit de pare-feu cross-platform **Windows / Linux**.  
**154+ tests** au total — rapport HTML interactif avec graphiques, recommandations et config client.

---

## ✅ Prérequis

- **Python 3.8+**
- **pip**

---

## ⚙️ Installation

### Windows
```bat
pip install -r requirements.txt
```

### Linux / macOS
```bash
pip install -r requirements.txt
# En cas de conflit système :
pip install -r requirements.txt --break-system-packages
```

---

## 🚀 Démarrage rapide

### Mode interactif (recommandé)
```bash
python firewall_tester.py
```
→ Un menu TUI s'ouvre dans le terminal. Tu choisis les modules, le proxy, le nom du client, etc.

### Mode CLI direct (sans menu)
```bash
python firewall_tester.py --no-tui --verbose
```

---

## 📋 Toutes les options CLI

| Option | Description |
|--------|-------------|
| `--no-tui` | Bypass le menu interactif, lance directement |
| `--modules url eicar c2 dns ssl app` | Choisir les modules (défaut : tous) |
| `--verbose` | Affiche chaque résultat en temps réel |
| `--no-html` | Ne génère pas de rapport HTML |
| `--output fichier.html` | Nom du fichier rapport HTML |
| `--json` | Exporte aussi en JSON |
| `--proxy http://user:pass@proxy:3128` | Proxy manuel (override config.json) |
| `--config autre_config.json` | Utiliser un fichier de config différent |

---

## 🖥️ Menu TUI — Navigation

```
[1-6]   Activer / désactiver un module
[7]     Changer le nom du fichier rapport
[8]     Activer / désactiver l'export JSON
[9]     Configurer le proxy (auto-détection + saisie manuelle)
[C]     Saisir les infos client / auditeur / ESN
[A]     Tout sélectionner / Tout désélectionner
[ENTRÉE] Lancer l'audit
[Q]     Quitter
```

---

## 🌐 Proxy — Comment ça marche

Le script détecte automatiquement le proxy dans cet ordre :

1. **Variables d'environnement** (`HTTPS_PROXY`, `HTTP_PROXY`)
2. **Registre Windows** (`Internet Settings > ProxyServer`)
3. **Saisie manuelle** via le menu [9] ou `--proxy`
4. **config.json** (`proxy.enabled: true`)

Formats acceptés :
```
http://proxy.entreprise.com:3128
http://username:password@proxy.entreprise.com:3128
```

---

## ⚙️ Configuration client (config.json)

Éditer `config.json` avant de lancer pour personnaliser le rapport :

```json
{
  "client": {
    "name": "Nom du Client SA",
    "logo_url": "https://client.com/logo.png",
    "contact": "dsi@client.fr"
  },
  "auditor": {
    "name": "Prénom Nom",
    "company": "Votre ESN",
    "email": "auditeur@esn.fr"
  },
  "audit": {
    "title": "Audit Pare-feu & Web Policy",
    "period_start": "2025-04-01",
    "period_end": "2025-04-03",
    "version": "1.0",
    "confidentiality": "CONFIDENTIEL"
  },
  "proxy": {
    "enabled": false,
    "url": "http://proxy:3128",
    "username": "",
    "password": ""
  }
}
```

---

## 📊 Modules de test (154+ tests)

| Module | Flag | Tests | Description |
|--------|------|-------|-------------|
| URL / Web Policy | `url` | 108 | Adult, social, streaming, IA, darkweb, crypto, gambling… |
| EICAR / Malware | `eicar` | 6 | Fichiers EICAR officiels + WiCAR |
| C2 / IPs | `c2` | 10 | Connexions TCP vers IPs/ports suspects |
| DNS Filtering | `dns` | 12 | Domaines malicieux, DGA, DoH bypass |
| SSL Inspection | `ssl` | 12 | Certs invalides, TLS old, chiffrements faibles |
| App Layer / WAF | `app` | 6 | User-Agent suspects, SQLi, XSS, path traversal |

### Catégories URL (108 tests)

| Catégorie | Sites testés | Sévérité |
|-----------|-------------|----------|
| 🔞 Adult | Pornhub, xvideos, OnlyFans, Chaturbate… (12) | 🔴 CRITIQUE |
| ☣️ Malware | URLhaus, WiCAR, Ransomware.org… (5) | 🔴 CRITIQUE |
| 📤 Data Exfil | Pastebin, transfer.sh, rentry.co… (4) | 🔴 CRITIQUE |
| 🕸️ Dark Web | Ahmia, Hidden Wiki, ZeroNet, I2P… (6) | 🔴 CRITIQUE |
| 🎣 Phishing | PhishTank, OpenPhish (2) | 🔴 CRITIQUE |
| ₿ Crypto | Binance, Coinbase, Kraken, OKX… (10) | 🟠 MAJEUR |
| 🎰 Gambling | Winamax, Betclic, PMU, Bet365… (8) | 🟠 MAJEUR |
| 🧅 Anonymizer | Tor, hide.me, ProxySite (3) | 🟠 MAJEUR |
| 🔐 VPN | NordVPN, Mullvad, ProtonVPN… (4) | 🟠 MAJEUR |
| 🛠️ Hacking Tools | Exploit-DB, Shodan, Kali… (5) | 🟠 MAJEUR |
| 💬 Social Media | TikTok, Telegram, Discord, Reddit… (16) | 🔵 MINEUR |
| 🎬 Streaming | YouTube, Netflix, Spotify, Disney+… (10) | 🔵 MINEUR |
| ☁️ Cloud Pro | SharePoint, OneDrive, Box, iCloud… (8) | 🔵 MINEUR |
| 🤖 IA / LLM | ChatGPT, Claude, Gemini, Copilot… (8) | 🔵 MINEUR |
| 📂 File Sharing | WeTransfer, Mega, Mediafire (3) | 🔵 MINEUR |
| ✅ Neutral | Google, Microsoft, Wikipedia, GitHub (4) | — |

---

## 📈 Rapport HTML

Le fichier `.html` s'ouvre directement dans n'importe quel navigateur.

**Contenu :**
- En-tête avec logo client, nom auditeur, période
- Note globale A/B/C/D/F
- Graphiques : barres de score par module + graphique SVG
- **Section URL par catégorie** : cliquer pour voir les sites testés + camembert bloqué/non bloqué
- Recommandations automatiques classées par sévérité (CRITIQUE / MAJEUR / MINEUR)
- Tables détaillées EICAR, C2, DNS, SSL, App Layer

---

## 🎯 Exemples d'utilisation

### Audit client complet avec proxy authentifié
```bash
python firewall_tester.py --no-tui --proxy http://admin:pass123@10.0.0.1:3128 --output audit_client.html --json --verbose
```

### Audit rapide URL + DNS uniquement
```bash
python firewall_tester.py --no-tui --modules url dns --verbose
```

### Mode interactif avec config client pré-remplie
```bash
# Éditer config.json avec les infos client, puis :
python firewall_tester.py
```

---

## 📈 Interprétation du score

| Grade | Score | Signification |
|-------|-------|---------------|
| **A** | ≥ 90% | Excellent — pare-feu bien configuré |
| **B** | ≥ 75% | Bon — quelques lacunes mineures |
| **C** | ≥ 60% | Moyen — améliorations nécessaires |
| **D** | ≥ 40% | Faible — configuration insuffisante |
| **F** | < 40% | Critique — pare-feu très permissif |


---

## 📄 Export PDF

Le rapport peut être exporté en PDF directement depuis le script.

### Option 1 — WeasyPrint (recommandé, pur Python)
```bash
pip install weasyprint
python firewall_tester.py --no-tui --pdf
```

### Option 2 — pdfkit + wkhtmltopdf
```bash
pip install pdfkit
# Installer wkhtmltopdf : https://wkhtmltopdf.org/downloads.html
# Windows : ajouter wkhtmltopdf au PATH
python firewall_tester.py --no-tui --pdf
```

### Depuis le menu TUI
Activer l'option **[P] Export PDF** avant de lancer l'audit.  
Le PDF est généré au même endroit que le HTML, avec le même nom (`rapport.pdf`).

> Si aucun moteur n'est installé, le script affiche les instructions d'installation et continue sans planter.

---

## ⚠️ Disclaimer légal

Utilisation réservée aux réseaux **dont vous êtes propriétaire ou pour lesquels vous disposez d'une autorisation écrite**.  
Article 323-1 du Code pénal (France) — accès frauduleux à un système informatique.
