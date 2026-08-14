# FirewallTester v4.0

Outil d'audit de pare-feu, de proxy et de politique web, depuis un poste utilisateur.
Compatible **Windows / Linux / macOS**, dépendance unique : `requests`.

Il exécute ~250 tests, distingue ce qu'il a **réellement prouvé** de ce qu'il n'a
pas pu déterminer, et produit un rapport HTML/PDF exploitable en livrable client.

## Installation

```bash
pip install -r requirements.txt
```

Sous Linux, en cas de conflit avec les paquets système :

```bash
pip install -r requirements.txt --break-system-packages
```

## Utilisation

Menu interactif (le plus simple) :

```bash
python firewall_tester.py
```

Ligne de commande :

```bash
python firewall_tester.py --no-tui --verbose --pdf
```

Vérifier le moteur de détection sans toucher au réseau :

```bash
python firewall_tester.py --self-test
```

## Antivirus / EDR sur le poste de test (important)

La chaîne de test **EICAR** est, par conception, reconnue par tous les antivirus.
Sur un poste protégé par un EDR (Sophos Intercept X, Defender…), deux risques :

- le **fichier source** est mis en quarantaine s'il contient la signature en clair ;
- le **process** est tué — et le script quarantiné — si la charge est présente en
  mémoire pendant l'exécution.

La v4.0.2 les neutralise **à la source** :

- le fichier ne contient **aucune** signature EICAR (ni brute, ni encodée, ni masquée)
  et **aucune** routine de déchiffrement/obfuscation — c'est justement ce genre de
  motif « packer » que les moteurs heuristiques flaggent ;
- les charges d'exploit du module WAF sont stockées en **fragments inertes**,
  assemblés uniquement à l'exécution : aucune chaîne d'attaque complète n'apparaît
  dans le source ;
- les modules `eicar` et `upload` sont **gelés par défaut** ; avec `--allow-eicar`,
  la charge EICAR est alors **téléchargée à la volée** depuis la source officielle,
  jamais présente dans le code. Les 10 autres modules tournent normalement.

Pour réellement exécuter les tests EICAR (par ex. pour mesurer un proxy distant),
**exclure d'abord le dossier de l'antivirus**, puis :

```bash
python firewall_tester.py --no-tui --allow-eicar
```

En menu interactif, la touche **[E]** active/désactive ces modules.

## Principes de mesure

C'est ce qui différencie la v4 : **un test qui ne prouve rien ne compte pas**.

| Attendu | Signification | Entre dans la note |
|---|---|---|
| `doit être bloqué` | catégorie de sécurité (malware, phishing, adulte, dark web…) | oui |
| `doit passer` | référence neutre, éditeur de sécurité, outil métier → détecte le **sur-blocage** | oui |
| `selon politique` | réseaux sociaux, IA, streaming, crypto, VPN… : dépend du client | non, taux affiché à part |
| `mesure` | information (débit, comportement du résolveur) | non |

| Observé | Signification |
|---|---|
| `bloqué` | preuve d'un filtrage (signature d'équipement, RST, sinkhole DNS, page de garde) |
| `non bloqué` | le flux a atteint sa destination |
| `indéterminé` | preuve insuffisante — **exclu du score**, listé en annexe A |

Chaque résultat porte un niveau de confiance : `certain` (preuve directe),
`probable` (faisceau d'indices), `faible` (à confirmer manuellement).

### Ce qui a été corrigé par rapport à la v3

- Les sites d'**éditeurs de sécurité** (Malwarebytes, abuse.ch, PhishTank, VirusTotal,
  CERT-FR…) ne sont plus classés « malware » : ils sont attendus **autorisés**, et les
  bloquer devient un constat de sur-blocage.
- La catégorie malware ne contient plus que des ressources **publiées pour être testées** :
  EICAR, AMTSO, Google Safe Browsing, WiCAR, domaines de test Cisco Umbrella.
- Les **pages de blocage en HTTP 200** sont détectées (Zscaler, Fortinet, Blue Coat,
  Olfeo, Squid, Umbrella, Netskope…), en en-tête comme dans le corps.
- Un nom d'éditeur cité dans un article ne déclenche plus de faux positif : la
  signature n'est retenue que sur une réponse courte ou dans les en-têtes.
- Un **403 ambigu** est déclaré indéterminé au lieu d'être compté comme un blocage.
- Les tests de ports visent `portquiz.net`, qui écoute sur **tous** les ports TCP :
  un refus est donc imputable au réseau, et non à un service absent côté serveur.
- Les protocoles (FTP, SSH, SMTP, IMAP) sont validés par **lecture de bannière** :
  une session TCP ouverte sans bannière révèle un proxy transparent.
- Les tests d'accès par **IP directe** résolvent le domaine à l'exécution (plus d'IP
  figées et périmées) et utilisent une requête HTTP brute avec Host + SNI.
- Le module SSL distingue le rejet **local** (bibliothèque du poste) du rejet **réseau**,
  et détecte un certificat invalide ré-émis par le proxy.
- Le DNS est interrogé par un résolveur intégré (UDP/TCP), ce qui donne le vrai code
  retour (NXDOMAIN, REFUSED) et permet de tester DoH, DoT et le DNS externe direct.
- Le module débit n'entre plus dans la note (il ne mesure pas un filtrage).

### Mesures de contrôle

Avant l'audit, l'outil vérifie la connectivité, la sortie HTTP en clair, l'interception
TLS (en comparant l'émetteur du certificat à la liste des autorités publiques), la
joignabilité de l'hôte de test des ports et du point d'écho HTTP. **Sans connectivité de
référence, aucun verdict « bloqué » n'est retenu.**

## Modules

| # | Module | Contenu |
|---|--------|---------|
| 1 | URL / Politique web | 133 URL réparties en 20 catégories |
| 2 | Malware / EICAR | téléchargement effectif du fichier de test, HTTP et HTTPS, ZIP |
| 3 | C2 / IP malveillantes | annuaires Tor, IRC, Telnet, SMB/RDP sortants, bogons |
| 4 | Filtrage DNS | résolution filtrée, DNS externe direct, DoH, DoT |
| 5 | Inspection SSL/TLS | certificats invalides, chiffrements faibles, TLS 1.0/1.1 |
| 6 | Couche applicative | SQLi, XSS, traversée, Log4Shell, Shellshock, UA de scanners |
| 7 | Contournement | IP directe, casse, point final, notation décimale, ports alternatifs |
| 8 | Protocoles alternatifs | FTP, SSH, SMTP, IMAP, MQTT avec lecture de bannière |
| 9 | Ports non standard | bases de données, administration, ports hauts |
| 10 | Exfiltration DNS | étiquettes longues, TXT, débit de requêtes |
| 11 | Upload de fichiers | EICAR, exécutable, script, archive protégée |
| 12 | Débit / QoS | débit et latence (informatif) |

## Options

| Option | Rôle |
|--------|------|
| `--no-tui` | lance directement, sans menu |
| `--modules url dns ssl …` | choix des modules |
| `--verbose` | détail de chaque test à l'écran |
| `--quiet` | sortie minimale |
| `--output rapport.html` | nom du rapport |
| `--pdf` | export PDF (WeasyPrint → Chrome/Edge → wkhtmltopdf) |
| `--json` | export des données brutes |
| `--no-html` | pas de rapport HTML |
| `--proxy http://user:pass@hote:3128` | proxy explicite |
| `--no-proxy` | ignorer le proxy système |
| `--timeout 10` | délai réseau (défaut 6 s) |
| `--config mon_config.json` | fichier de configuration |
| `--allow-eicar` | exécuter réellement les modules eicar/upload (exclure le dossier de l'AV avant) |
| `--list-tests` | inventaire des tests |
| `--self-test` | contrôle hors ligne du moteur de détection |

## Configuration (`config.json`)

```json
{
  "client":  { "name": "Client SA", "logo_url": "", "contact": "dsi@client.fr" },
  "auditor": { "name": "Prénom Nom", "company": "Votre ESN", "email": "audit@esn.fr" },
  "audit":   { "title": "Audit de pare-feu et de politique web",
               "confidentiality": "CONFIDENTIEL", "scope": "Siège — VLAN bureautique" },
  "proxy":   { "enabled": false, "url": "", "username": "", "password": "" },
  "policy":  { "social_media": "blocked", "ai_llm": "blocked" }
}
```

La section `policy` permet d'aligner l'outil sur la politique du client : une catégorie
déclarée `blocked` (ou `allowed`) bascule du hors-note vers la note.

## Export PDF

Aucune installation n'est nécessaire si **Chrome ou Edge** est présent : l'outil les
détecte et imprime le rapport. Sinon `pip install weasyprint`, ou bouton
« Imprimer / PDF » du rapport HTML.

## Note globale

Calculée uniquement sur les tests concluants et non discrétionnaires.

| Note | Score | Signification |
|------|-------|---------------|
| A | ≥ 90 % | pare-feu correctement durci |
| B | ≥ 75 % | bon niveau, lacunes ciblées |
| C | ≥ 60 % | protection partielle |
| D | ≥ 40 % | filtrage insuffisant |
| F | < 40 % | réseau très permissif |

## Avertissement légal

À utiliser uniquement sur des réseaux dont vous êtes propriétaire ou pour lesquels vous
disposez d'une autorisation écrite. En France, l'accès frauduleux à un système
d'information est réprimé par l'article 323-1 du Code pénal.

Aucun code malveillant n'est exécuté ni téléchargé : l'outil ne sollicite que des
ressources publiées à des fins de test (EICAR, AMTSO, Google Safe Browsing, WiCAR,
domaines de test Cisco Umbrella) et des sites publics légitimes.
