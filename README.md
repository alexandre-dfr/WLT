# FirewallTester v3.0

Outil d'audit de pare-feu et de politique web, compatible **Windows / Linux / macOS**.
Il lance ~150 tests et produit un rapport HTML lisible (scores, recommandations, tables détaillées).

## Installation

Prérequis : **Python 3.8+** et **pip**.

```bash
pip install -r requirements.txt
```

Sous Linux, en cas de conflit avec les paquets système :

```bash
pip install -r requirements.txt --break-system-packages
```

## Utilisation

### Menu interactif (le plus simple)

```bash
python firewall_tester.py
```

Un menu s'ouvre dans le terminal : choisissez les modules, le proxy et les infos
client, puis appuyez sur Entrée pour lancer l'audit.

### Ligne de commande (sans menu)

```bash
python firewall_tester.py --no-tui --verbose
```

Le rapport HTML est généré dans le dossier courant et s'ouvre dans n'importe quel navigateur.

## Options principales

| Option | Rôle |
|--------|------|
| `--no-tui` | Lance directement, sans le menu |
| `--modules url dns ssl ...` | Choisir les modules (défaut : tous) |
| `--verbose` | Affiche chaque test en temps réel |
| `--output rapport.html` | Nom du fichier HTML |
| `--json` | Exporte aussi un fichier JSON |
| `--pdf` | Exporte aussi un PDF (voir plus bas) |
| `--no-html` | Ne génère pas de rapport HTML |
| `--proxy http://user:pass@host:3128` | Proxy manuel |
| `--config mon_config.json` | Fichier de configuration |

## Modules disponibles

| Flag | Module | Ce qui est testé |
|------|--------|------------------|
| `url` | URL / Web Policy | Adult, social, streaming, IA, crypto, gambling, darkweb... |
| `eicar` | EICAR / Malware | Téléchargements de fichiers de test antivirus |
| `c2` | C2 / IPs | Connexions TCP vers IP et ports suspects |
| `dns` | DNS | Domaines malicieux, DGA, DoH |
| `ssl` | SSL / TLS | Certificats invalides, TLS ancien, chiffrements faibles |
| `app` | WAF / IPS | User-Agent suspects, SQLi, XSS, path traversal |
| `bypass` | Contournement | IP directe, encodage URL, casse, sous-domaines |
| `proto` | Protocoles | FTP, SSH, MQTT, WebSocket, SMTP, IMAP |
| `ports` | Ports non standard | Ports HTTP/HTTPS alternatifs, bases de données exposées |
| `dns_exfil` | Exfiltration DNS | Requêtes TXT, DGA, tunnels DNS |
| `upload` | Upload suspect | Envoi de fichiers EICAR, EXE, scripts |
| `bandwidth` | Débit / QoS | Détection de throttling |

## Proxy

Le proxy est détecté automatiquement dans cet ordre :

1. Variables d'environnement (`HTTPS_PROXY`, `HTTP_PROXY`)
2. Registre Windows (paramètres Internet)
3. Menu interactif ou option `--proxy`
4. Fichier `config.json`

Formats acceptés :

```
http://proxy.entreprise.com:3128
http://utilisateur:motdepasse@proxy.entreprise.com:3128
```

## Configuration client (config.json)

Optionnel. Éditez `config.json` pour personnaliser l'en-tête du rapport :

```json
{
  "client":  { "name": "Client SA", "logo_url": "", "contact": "dsi@client.fr" },
  "auditor": { "name": "Prénom Nom", "company": "Votre ESN", "email": "audit@esn.fr" },
  "audit":   { "title": "Audit Pare-feu & Web Policy", "confidentiality": "CONFIDENTIEL" },
  "proxy":   { "enabled": false, "url": "http://proxy:3128", "username": "", "password": "" }
}
```

## Export PDF

Nécessite l'un des deux moteurs :

```bash
pip install weasyprint      # recommandé, pur Python
# ou
pip install pdfkit          # nécessite aussi wkhtmltopdf (https://wkhtmltopdf.org)
```

Puis :

```bash
python firewall_tester.py --no-tui --pdf
```

Si aucun moteur n'est installé, le script continue sans planter et affiche la marche à suivre.

## Score

| Note | Score | Signification |
|------|-------|---------------|
| A | ≥ 90% | Pare-feu bien configuré |
| B | ≥ 75% | Bon, quelques lacunes |
| C | ≥ 60% | Moyen, à améliorer |
| D | ≥ 40% | Faible |
| F | < 40% | Très permissif |

## Exemples

```bash
# Audit complet avec proxy authentifié et export JSON
python firewall_tester.py --no-tui --proxy http://admin:pass@10.0.0.1:3128 --json --verbose

# Audit rapide URL + DNS uniquement
python firewall_tester.py --no-tui --modules url dns --verbose
```

## Avertissement légal

À utiliser uniquement sur des réseaux dont vous êtes propriétaire ou pour lesquels
vous disposez d'une autorisation écrite. En France, l'accès frauduleux à un système
informatique est réprimé par l'article 323-1 du Code pénal.
