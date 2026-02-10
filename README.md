# Argos-Recon

**Argos-Recon** est un moteur de reconnaissance active orienté sécurité, conçu pour analyser rapidement la surface d’attaque exposée d’une cible web (HTTP, TLS, DNS, CMS) de manière **contrôlée, déterministe et explicable**.

> 🎯 Objectif : fournir une **cartographie fiable des signaux de faiblesse** avant toute phase d’exploitation.

---

## Version actuelle

- **Version** : `v0.2.7 Stable`
- **Statut** : Stable (tests + lint validés)
- **Public cible** : étudiants cybersécurité, pentesters juniors, équipes blue/red en phase de recon

---

## Objectifs du projet

- Centraliser la **reconnaissance active** (HTTP / TLS / DNS / CMS)
- Détecter des **mauvaises configurations exploitables**
- Produire des **signaux et findings structurés**, exploitables humainement
- Garantir :
  - une **empreinte réseau maîtrisée** (budget + concurrence)
  - une **consommation mémoire bornée** (streaming strict)
  - une **logique explicable** (no black box)

Argos-Recon **n’exploite rien** : il observe, mesure et signale.

---

## Architecture générale

```
Target URL
   │
   ├─ DNS Scanner         → Enregistrements, erreurs, signaux
   ├─ TLS Scanner         → Certificat, validité, CN, protocole
   ├─ HTTP Scanner        → Baseline + probes (streaming borné)
   ├─ CMS Detection       → Règles CMS + heuristiques
   │
   ├─ Signal Engine       → Normalisation des signaux
   ├─ Playbooks (PB1–PB5) → Findings corrélés
   │
   └─ Rapport final       → JSON structuré (RunReportV1)
```

---

## Fonctionnalités actuelles (v0.2.7)

### HTTP
- Requête baseline (`/`)
- Probing contrôlé de chemins courants :
  - `/robots.txt`
  - `/sitemap.xml`
  - `/wp-login.php`
  - `/xmlrpc.php`
- **Streaming strict** :
  - lecture par chunks
  - limite mémoire `max_bytes`
  - détection explicite de troncature (`response_truncated`)
  - snippet d’analyse borné (ex: 2048 chars)

### TLS
- Handshake en mode **reconnaissance volontaire** :
  - `ssl.CERT_NONE`
  - accepte certificats expirés / auto-signés
- Extraction :
  - CN (Common Name)
  - Issuer (Organization)
  - Protocole / Cipher
  - Date d’expiration (parsing robuste)
- Détection :
  - certificat expiré (`tls.is_expired`)
  - mismatch CN / host (`tls.subject_mismatch`)

### DNS
- Résolution A / AAAA / MX / NS / TXT / SOA
- Gestion des erreurs DNS
- Base pour détection de mauvaise délégation / takeover (selon playbooks)

### CMS
- Détection par règles (WordPress inclus)
- Extraction version CMS (readme, meta generator, headers)
- Corrélation CVE locale (si base fournie)

---

## Système de signaux et playbooks

### Signaux
Les scanners produisent des **SignalV1** normalisés :
- `source` (`tls`, `http`, `dns`, `cms`)
- `value` (booléen ou valeur structurée selon le signal)
- `signal_confidence` (0.0 → 1.0)

### Playbooks actifs
| ID  | Description |
|----|------------|
| PB1 | Faiblesses TLS (expiration, mismatch) |
| PB2 | Headers HTTP (exposition / posture) |
| PB3 | Indices DNS (SPF/MX/etc.) |
| PB4 | Indices takeover (DNS + HTTP signatures) |
| PB5 | CMS WordPress + CVE (si base) |

Chaque playbook produit des **FindingV1** :
- sévérité (`low`, `medium`, `high`)
- score explicite
- signaux déclencheurs
- preuves associées

---

## Installation

### Prérequis
- Python **3.11+** recommandé
- Windows / Linux / macOS

### Installation
```bash
python -m venv .venv

# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux/macOS
# source .venv/bin/activate

pip install -r requirements.txt
```

---

## Lancer l’interface web

```bash
uvicorn main:create_app --reload
```

- API : http://127.0.0.1:8000
- Swagger : http://127.0.0.1:8000/docs

---

## Tests, linting, format

### Tests
```bash
python -m pytest -q
```

### Ruff + Black
```bash
black .
ruff check . --select E,F,I --ignore E501
```

---

## Sécurité & avertissement

⚠️ **Usage autorisé uniquement**

Argos-Recon est un outil de **reconnaissance active**.

Choix d’architecture intentionnels :
- Validation SSL désactivée (`ssl.CERT_NONE`, `verify=False`) pour analyser des cibles mal configurées
- Probing léger de chemins communs
- User-Agent standard (ou configuré côté code)

👉 N’utilisez cet outil **que** sur des cibles dont vous êtes propriétaire ou avec autorisation explicite.

---

## Prochaines étapes envisagées (Roadmap)

### Phase 1 – Robustesse & fiabilité (v0.3.x)
Gestion avancée des erreurs réseau (timeouts, retries, backoff progressif).
Prise en charge explicite des réponses 429 et 503 (réduction automatique de la charge).
Budget de requêtes dynamique par cible afin de limiter l’impact sur les services analysés.
Mode Reconnaissance passive (DNS, certificats, métadonnées publiques) sans requêtes HTTP actives.
Journalisation détaillée des erreurs et décisions du moteur.

### Phase 2 – Couverture fonctionnelle (Playbooks)
Détection automatique des interfaces OpenAPI / Swagger et extraction des routes exposées.
Identification des surfaces d’authentification (login, admin, portails sensibles).
Analyse avancée de la posture TLS (versions supportées, suites faibles, HSTS).
Détection de WAF et reverse-proxy courants (Cloudflare, AWS WAF, Akamai, etc.).
Recherche de fichiers sensibles exposés (.env, backups, archives, fichiers de configuration).
Détection de technologies Web et frameworks côté client (approche similaire à Wappalyzer).
Détection des risques de subdomain takeover (CNAME orphelins).

### Phase 3 – Packaging & distribution
Interface CLI unifiée (binaire standalone).
Export des rapports en plusieurs formats : JSON, Markdown, CSV et HTML.
Versioning sémantique et changelog structuré.
Image Docker officielle pour exécution isolée.
Système de plugins permettant d’étendre les playbooks sans modifier le cœur.

### Phase 4 – Qualité & automatisation
Pipeline CI/CD avec linting, tests unitaires et tests d’intégration.
Vérifications automatiques de sécurité du code (analyse statique).
Surveillance des dépendances et alertes de vulnérabilités.
Tests de performance et de montée en charge.

### Phase 5 – Interface & expérience utilisateur
Historique des scans et comparaison entre exécutions.
Vue “findings” orientée impact et recommandations.
Suivi de progression des scans en temps réel.
Système de gestion des faux positifs.

### Phase 6 – Intégrations

Webhooks (Slack, Teams, Discord).
Création automatique de tickets (Jira, GitLab).
Stockage externe des rapports (S3 compatible).
---

## Licence

Projet pédagogique / expérimental. Licence à définir selon usage futur.
